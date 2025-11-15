from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, ARP
import threading
import time
from collections import deque, defaultdict

app = Flask(__name__)

alerts = deque(maxlen=100)
LOCK = threading.Lock()

# Rules for detection

def add_alert(alert_type, description, extra=None):
    with LOCK:
        alerts.appendleft({
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "type": alert_type,
            "description": description,
            "extra": extra or {}
        })


def detect_port_scan(pkt):
    if IP in pkt and TCP in pkt:
        flags = pkt[TCP].flags
        if flags == "S":  # ONLY FOR SYN PACKETS
            add_alert("Possible Port Scan", f"SYN packet from {pkt[IP].src}")


def detect_arp_spoof(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # ARP reply
        add_alert("ARP Event", f"ARP reply detected from {pkt[ARP].psrc}")


# PACKET HANDLER

def packet_handler(pkt):
    detect_port_scan(pkt)
    detect_arp_spoof(pkt)


# SNIFFER THREAD

def start_sniffer():
    sniff(prn=packet_handler, store=False)


# ROUTES FOR FLASK

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/alerts")
def get_alerts():
    with LOCK:
        return jsonify(list(alerts))


if __name__ == "__main__":
    t = threading.Thread(target=start_sniffer, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=True)
