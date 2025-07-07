import scapy.all as scapy
import pandas as pd
import numpy as np
import time
import ipaddress
import re
import joblib
from scapy.layers.inet import IP, TCP, UDP
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import torch.optim as optim
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import plotly.graph_objs as go
import dash
from dash import Dash, dcc, html
import statsmodels.api as sm
import psutil
from datetime import datetime
import threading
import plotly.graph_objs as go
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import statsmodels.api as sm
from collections import deque
from sklearn.linear_model import LinearRegression
from scapy.all import scapy
from scapy.all import sniff
from sklearn.preprocessing import PolynomialFeatures
from scapy.layers.l2 import ARP
import seaborn as sns
import requests
import json
from collections import defaultdict
from scapy.all import sniff, ARP, TCP, IP
import geoip2.database



# File Paths
CSV_FILE = "/Users/dhrishitaparve/Desktop/BSCI/network_data.csv"
RF_MODEL_FILE = "/Users/dhrishitaparve/Desktop/BSCI/random_forest_model.pkl"
LSTM_MODEL_FILE = "/Users/dhrishitaparve/Desktop/BSCI/lstm_model.pth"


# Email Configuration
#SENDER_EMAIL = "mahimu1853@gmail.com"
#RECEIVER_EMAIL = "dhrishitap18@gmail.com"
#PASSWORD = "ysvf qctv hjkk zoii"   

TEAMS_WEBHOOK_URL =  "https://bostonscientific.webhook.office.com/webhookb2/c2a88124-855b-48f1-b660-79954adb651e@b5b8b483-5597-4ae7-8e27-fcc464a3b584/IncomingWebhook/1c8fee2044a24e2ba54d2495f15fa71f/96b7b5af-a9f2-4aa1-8b7d-9abf85b43ae5/V23CddetxeRsKJB556JnVr2TDHLyCg_UqyEY6oUpb2H5Y1"
INTERFACE = "eth0"
# GeoIP Database Reader
GEOIP_DB = '/Users/dhrishitaparve/Desktop/BSCI/GeoLite2-City.mmdb'

# Alert CSV File
ALERT_LOG_FILE = 'alerts.csv'

# Attack thresholds
SYN_THRESHOLD = 5
BRUTE_FORCE_THRESHOLD = 5

# Track counts
syn_counter = defaultdict(int)
brute_force_counter = defaultdict(int)
arp_spoof_tracker = {}

# Load GeoIP DB
geoip_reader = geoip2.database.Reader(GEOIP_DB)

def get_geoip_location(ip):
    try:
        response = geoip_reader.city(ip)
        city = response.city.name or "Unknown City"
        country = response.country.name or "Unknown Country"
        return f"{city}, {country}"
    except:
        return "Unknown Location"

def log_alert(alert_type, src_ip, extra=""):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    location = get_geoip_location(src_ip)
    data = {
        "Timestamp": timestamp,
        "Alert Type": alert_type,
        "Source IP": src_ip,
        "Location": location,
        "Details": extra
    }
    df = pd.DataFrame([data])
    df.to_csv(ALERT_LOG_FILE, mode='a', index=False, header=not pd.io.common.file_exists(ALERT_LOG_FILE))
    print(f"[ALERT] {timestamp} - {alert_type} from {src_ip} - {location}")
    send_teams_alert(alert_type, src_ip, location, extra)

def send_teams_alert(alert_type, src_ip, location, extra=""):
    message = {
        "text": f"⚠️ *{alert_type} Detected!*\n"
                f"🔹 IP: {src_ip}\n"
                f"📍 Location: {location}\n"
                f"📄 Details: {extra}"
    }
    try:
        requests.post(TEAMS_WEBHOOK_URL, json=message)
    except Exception as e:
        print("Failed to send Teams alert:", e)

def detect_attack(pkt):
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src

        # SYN Flood Detection
        if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
            syn_counter[src_ip] += 1
            print(f"[DEBUG] SYN packet from {src_ip} → Count: {syn_counter[src_ip]}")
            if syn_counter[src_ip] > SYN_THRESHOLD:
                print(f"[ALERT] 🚨 SYN Flood Detected from {src_ip} with {syn_counter[src_ip]} SYNs")
                log_alert("SYN Flood Attack", src_ip, f"Count: {syn_counter[src_ip]}")
                syn_counter[src_ip] = 0

        # Brute Force Detection (Failed TCP connections without SYN/ACK)
        elif pkt.haslayer(TCP) and pkt[TCP].flags in ['R', 'F']:
            brute_force_counter[src_ip] += 1
            print(f"[DEBUG] Failed TCP (R/F) from {src_ip} → Count: {brute_force_counter[src_ip]}")
            if brute_force_counter[src_ip] > BRUTE_FORCE_THRESHOLD:
                print(f"[ALERT] 🔐 Brute Force Detected from {src_ip}")
                log_alert("Brute Force Attack", src_ip, f"Failed attempts: {brute_force_counter[src_ip]}")
                brute_force_counter[src_ip] = 0

    # ARP Spoofing Detection
    if pkt.haslayer(ARP) and pkt[ARP].op == 2:
        hw = pkt[ARP].hwsrc
        ip = pkt[ARP].psrc
        if ip in arp_spoof_tracker and arp_spoof_tracker[ip] != hw:
            print(f"[ALERT] 🧅 ARP Spoofing Detected for {ip} (MAC: {arp_spoof_tracker[ip]} → {hw})")
            log_alert("ARP Spoofing", ip, f"MAC Changed: {arp_spoof_tracker[ip]} → {hw}")
        arp_spoof_tracker[ip] = hw


# Feature Extraction
def extract_features(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        pkt_length = len(packet)

        if TCP in packet:
            flags = packet[TCP].flags
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            flags = 0
            sport = packet[UDP].sport
            dport = packet[UDP].dport
        else:
            flags, sport, dport = 0, 0, 0

        return [time.time(), src_ip, dst_ip, protocol, pkt_length, flags, sport, dport]
    return None

# Convert IP to Integer
def ip_to_int(ip):
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0

# Preprocess Data
def preprocess_data(df):
    df['src_ip'] = df['src_ip'].apply(ip_to_int)
    df['dst_ip'] = df['dst_ip'].apply(ip_to_int)

    # Ensure all columns are numeric
    numeric_cols = ['src_ip', 'dst_ip', 'protocol', 'length', 'flags', 'sport', 'dport']
    df[numeric_cols] = df[numeric_cols].apply(pd.to_numeric, errors='coerce')

    df.fillna(0, inplace=True)  # Handle NaNs
    return df[numeric_cols]

# Live Packet Capture
def capture_live_packets(packet_limit=500):
    print(f"🔴 Capturing {packet_limit} packets... Press CTRL+C to stop early.")
    captured_data = []

    def process_packet(packet):
        features = extract_features(packet)
        if features:
            captured_data.append(features)

    sniff(prn=process_packet, store=False, count=packet_limit)

    df = pd.DataFrame(captured_data, columns=['timestamp', 'src_ip', 'dst_ip', 'protocol', 'length', 'flags', 'sport', 'dport'])
    df.to_csv(CSV_FILE, index=False)
    print(f"✅ Network traffic saved to '{CSV_FILE}'")

# Train Random Forest Model
def train_random_forest():
    df = pd.read_csv(CSV_FILE)
    df.dropna(inplace=True)

    X = preprocess_data(df)
    y = np.random.randint(0, 2, size=len(X))  

    rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
    rf_model.fit(X, y)

    joblib.dump(rf_model, RF_MODEL_FILE)
    print(f"✅ Random Forest Model saved at {RF_MODEL_FILE}")

# Define LSTM Model
class LSTMAnomalyDetector(nn.Module):
    def __init__(self, input_size, hidden_size=64, num_layers=2):
        super(LSTMAnomalyDetector, self).__init__()
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, 1)

    def forward(self, x):
        out, _ = self.lstm(x)
        out = self.fc(out[:, -1, :])
        return out

# Train LSTM Model
def train_lstm():
    df = pd.read_csv(CSV_FILE)
    df.dropna(inplace=True)

    X = preprocess_data(df)
    X = StandardScaler().fit_transform(X)  # Normalize features

    # Convert to PyTorch tensor
    X_tensor = torch.tensor(X, dtype=torch.float32).unsqueeze(1)  # Adding extra dimension for LSTM
    y_tensor = torch.tensor(np.random.randint(0, 2, size=len(X)), dtype=torch.float32).unsqueeze(1)

    dataset = TensorDataset(X_tensor, y_tensor)
    dataloader = DataLoader(dataset, batch_size=32, shuffle=True)

    model = LSTMAnomalyDetector(input_size=X.shape[1])
    criterion = nn.BCEWithLogitsLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

    # Training loop
    for epoch in range(10):
        for batch_X, batch_y in dataloader:
            optimizer.zero_grad()
            outputs = model(batch_X)
            loss = criterion(outputs, batch_y)
            loss.backward()
            optimizer.step()
        print(f"Epoch {epoch+1}, Loss: {loss.item()}")

    torch.save(model.state_dict(), LSTM_MODEL_FILE)
    print(f"✅ LSTM Model saved at {LSTM_MODEL_FILE}")

# Load LSTM Model
def load_lstm_model():
    model = model = LSTMAnomalyDetector(input_size=7)  
    model.load_state_dict(torch.load(LSTM_MODEL_FILE))
    return model

        
# Global variables to store data
timestamps = []
latencies = []
download_speeds = []
upload_speeds = []
forecasted_bandwidth = []

# Function to monitor latency and bandwidth
def monitor_latency_and_bandwidth():
    while True:
        net_io = psutil.net_io_counters()
        latency = net_io.packets_recv  # Latency metric
        net_if = psutil.net_if_addrs()
        interface_name = 'en0' 
        if interface_name in net_if:
            download_speed = net_io.bytes_recv
            upload_speed = net_io.bytes_sent
        else:
            download_speed = 0
            upload_speed = 0

        current_time = time.time()

        # Append data
        timestamps.append(current_time)
        latencies.append(latency)
        download_speeds.append(download_speed)
        upload_speeds.append(upload_speed)

        # Limit the number of points to display
        if len(timestamps) > 100:
            timestamps.pop(0)
            latencies.pop(0)
            download_speeds.pop(0)
            upload_speeds.pop(0)

        time.sleep(1)

# Create figure and axes for plotting
fig, (ax1, ax2, ax3, ax4) = plt.subplots(4, 1, figsize=(10, 10))

# Function to update the plot during animation
def update_plot(frame):
    ax1.clear()
    ax2.clear()
    ax3.clear()
    ax4.clear()

    # Plot real-time data
    ax1.plot(timestamps, latencies, label="Latency")
    ax1.set_title("Latency (Packets)")
    ax1.set_xlabel("Time")
    ax1.set_ylabel("Latency (Packets)")

    ax2.plot(timestamps, download_speeds, label="Download Speed", color='green')
    ax2.set_title("Download Speed (Bytes/sec)")
    ax2.set_xlabel("Time")
    ax2.set_ylabel("Download Speed (Bytes/sec)")

    ax3.plot(timestamps, upload_speeds, label="Upload Speed", color='red')
    ax3.set_title("Upload Speed (Bytes/sec)")
    ax3.set_xlabel("Time")
    ax3.set_ylabel("Upload Speed (Bytes/sec)")

    # Forecasting future network bandwidth using Linear Regression
    if len(timestamps) > 10:
        X = np.array(timestamps).reshape(-1, 1)
        y = np.array(download_speeds)
        model = LinearRegression()
        model.fit(X, y)
        future_timestamps = np.array([timestamps[-1] + i for i in range(1, 11)]).reshape(-1, 1)
        future_predictions = model.predict(future_timestamps)

        ax4.plot(timestamps, download_speeds, label="Actual Bandwidth", color='blue')
        ax4.plot(future_timestamps, future_predictions, label="Forecasted Bandwidth", linestyle='dashed', color='orange')
        ax4.set_title("Network Bandwidth Forecast")
        ax4.set_xlabel("Time")
        ax4.set_ylabel("Download Speed (Bytes/sec)")
        ax4.legend()
        
    fig.tight_layout()

# Start monitoring in a separate thread
monitor_thread = threading.Thread(target=monitor_latency_and_bandwidth)
monitor_thread.daemon = True
monitor_thread.start()
cpu_usage = psutil.cpu_percent(interval=1)
memory_usage = psutil.virtual_memory().percent

# Animate the plot
ani = animation.FuncAnimation(fig, update_plot, interval=1000)

# Main execution
if __name__ == "__main__":
    capture_live_packets(500)  # Capture packets
    train_random_forest()  # Train Random Forest model
    train_lstm()  # Train LSTM model
    plt.show()  # Show animated plots
    
    
   