# Network Visualizer
A real-time network monitoring tool built with Python, Scapy, and Flask.  
Shows suspicious activity on a live web site.

# FEATURES
- Packet sniffing with Scapy
- ARP event detection
- Real-time dashboard with automatic refresh
- Port scan detection
- Flask serving JSON alerts

# Running instructions
1. Clone the repository
git clone https://github.com/aaronsiuthani/NetworkVisualiser.git

2. Create the virtual environment and activate it
python3 -m venv .venv
source .venv/bin/activate


3. Install dependencies by running
   'pip install flask scapy'

4. Run the sniffer:
   'sudo python3 app.py'

5. Open the website
   'http://localhost:5000'

# Future improvements
Add live charts or graphs
Store the alerts into a database
Add information lookup for specific devices

