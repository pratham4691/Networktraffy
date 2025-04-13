import os
import threading
import logging
import smtplib
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import pandas as pd
import pickle
from flask import Flask, jsonify, render_template
from flask_socketio import SocketIO, emit
import requests

# Flask and SocketIO initialization
app = Flask(__name__)
socketio = SocketIO(app)

# Logging setup
logging.basicConfig(filename="alerts.log", level=logging.INFO, format="%(asctime)s - %(message)s")

# Global variables
MODEL_FILE = "traffic_model.pkl"
SCALER_FILE = "scaler.pkl"
THREAT_INTELLIGENCE_URL = "https://example.com/malicious-ips"  # Replace with a real API
BLOCKED_IPS = set()
THREAT_IPS = set()

# Email alert configuration
EMAIL_SENDER = "your_email@example.com"
EMAIL_PASSWORD = "your_password"
EMAIL_RECIPIENT = "recipient_email@example.com"

# Load or initialize the model
if os.path.exists(MODEL_FILE):
    with open(MODEL_FILE, "rb") as f:
        model = pickle.load(f)
else:
    model = RandomForestClassifier()
    print("No pre-trained model found. Please train the model first.")

# Load or initialize the scaler
if os.path.exists(SCALER_FILE):
    with open(SCALER_FILE, "rb") as f:
        scaler = pickle.load(f)
else:
    scaler = StandardScaler()
    print("No scaler found. Please preprocess and train the data first.")

# Threat intelligence integration
def fetch_threat_intelligence():
    """
    Fetch known malicious IPs from a threat intelligence source.
    """
    global THREAT_IPS
    try:
        response = requests.get(THREAT_INTELLIGENCE_URL)
        if response.status_code == 200:
            THREAT_IPS = set(response.json().get("malicious_ips", []))
            print(f"Fetched {len(THREAT_IPS)} malicious IPs from threat intelligence.")
        else:
            print("Failed to fetch threat intelligence.")
    except Exception as e:
        print(f"Error fetching threat intelligence: {e}")

# Feature extraction
def extract_features(packet):
    """
    Extract relevant features from a packet for analysis.
    """
    try:
        features = {
            "packet_size": len(packet),
            "protocol": 1 if packet.haslayer(TCP) else 2 if packet.haslayer(UDP) else 0,
            "src_ip": packet[IP].src if packet.haslayer(IP) else "unknown",
            "dst_ip": packet[IP].dst if packet.haslayer(IP) else "unknown",
            "src_port": packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else 0,
            "dst_port": packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else 0,
        }
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

# Alerting
def send_email_alert(alert_message):
    """
    Sends an email alert for a detected event.
    """
    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECIPIENT, alert_message)
        print(f"Email alert sent: {alert_message}")
    except Exception as e:
        print(f"Failed to send email alert: {e}")

def log_and_alert(alert_message):
    """
    Logs the alert and notifies via WebSocket and email.
    """
    logging.info(alert_message)
    socketio.emit("new_alert", {"message": alert_message})
    send_email_alert(alert_message)

# Real-time packet processing
def process_packet(packet):
    """
    Process each packet, analyze it, and take action.
    """
    features = extract_features(packet)
    if features:
        src_ip = features["src_ip"]
        dst_ip = features["dst_ip"]

        # Check against threat intelligence
        if src_ip in THREAT_IPS or dst_ip in THREAT_IPS:
            alert_message = f"THREAT INTELLIGENCE ALERT: Malicious IP detected - {src_ip} or {dst_ip}."
            log_and_alert(alert_message)
            BLOCKED_IPS.add(src_ip)
            return

        # Convert features to DataFrame for model input
        df = pd.DataFrame([features])
        df["protocol"] = df["protocol"].astype(int)
        df["packet_size"] = df["packet_size"].astype(int)
        df_scaled = scaler.transform(df[["packet_size", "protocol"]])

        # Predict using the trained model
        prediction = model.predict(df_scaled)
        if prediction[0] == 1:  # Malicious packet detected
            alert_message = f"MACHINE LEARNING ALERT: Malicious traffic detected from {src_ip} to {dst_ip}."
            log_and_alert(alert_message)
            BLOCKED_IPS.add(src_ip)

# Real-time packet sniffing
def start_sniffing(interface="eth0"):
    """
    Start sniffing packets in real-time.
    """
    print(f"Starting packet sniffing on interface {interface}...")
    sniff(iface=interface, prn=process_packet, store=False)

# Flask dashboard
@app.route("/")
def dashboard():
    """
    Render the main dashboard.
    """
    return jsonify({"message": "Network Traffic Analyzer is running."})

@app.route("/alerts", methods=["GET"])
def get_alerts():
    """
    Retrieve alerts logged in the system.
    """
    with open("alerts.log", "r") as f:
        alerts = f.readlines()
    return jsonify(alerts)

@app.route("/blocked_ips", methods=["GET"])
def get_blocked_ips():
    """
    Retrieve the list of blocked IPs.
    """
    return jsonify(list(BLOCKED_IPS))

# Main function
if __name__ == "__main__":
    # Fetch threat intelligence
    fetch_threat_intelligence()

    # Start the packet sniffing in a separate thread
    sniff_thread = threading.Thread(target=start_sniffing, args=("eth0",))
    sniff_thread.daemon = True
    sniff_thread.start()

    # Start the Flask dashboard
    socketio.run(app, host="0.0.0.0", port=5000)