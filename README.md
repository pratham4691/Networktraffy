# Networktraffy
Setup Instructions:
Install Dependencies:

bash

pip install scapy pandas sklearn flask flask-socketio requests

Train the Model:

Collect training data and save it as traffic_model.pkl and scaler.pkl.

Run the Analyzer:

bash

sudo python3 network_traffic_analyzer_advanced.py

Access the Dashboard:

Alerts: http://127.0.0.1:5000/alerts
Blocked IPs: http://127.0.0.1:5000/blocked_ips
