# Real-Time-Network-Intrusion-Detection-System

An intelligent, modular, and real-time intrusion detection and network monitoring system built in Python. This system leverages **Scapy**, **Machine Learning (Random Forest & LSTM)**, **GeoIP**, **Matplotlib**, and **Microsoft Teams alerts** to detect and visualize cyber threats on live networks.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Dataset](#dataset)
- [Approach (Flowchart)](#approach-flowchart)
- [Woking of the Project](#working-of-the-project)
- [Demo](#demo)
- [Contact](#contact)

## Introduction

A Python-based real-time network intrusion detection and monitoring system using Scapy, machine learning (Random Forest + LSTM), Dash, and alerting via Microsoft Teams. This system can detect various types of network anomalies such as brute force attacks, SYN floods, and ARP spoofing. It also provides live bandwidth and latency monitoring, GeoIP-based location tagging of suspicious IPs, and a web dashboard for visualization.

## Features

- 🔍 **Live Packet Sniffing**: Captures and analyzes packets in real-time using Scapy.
- 🤖 **Anomaly Detection**: ML-based attack detection using Random Forest and LSTM models.
- 🌐 **GeoIP Tagging**: Maps attacker IP addresses to physical locations.
- 📊 **Dash Web UI**: Visual dashboard for real-time metrics (bandwidth, latency, attack logs).
- 📩 **Alerts via Microsoft Teams**: Notifies immediately of suspicious activity.
- 📡 **Latency & Bandwidth Monitoring**: Real-time tracking of network performance.


## 📁 Dataset

- For training the models:
  - **Custom Packet Capture Data**: Labeled packet statistics captured from real network traffic.
  - **Public Datasets (optional)**: CICIDS2017, UNSW-NB15, or KDDCup99 can be used to enhance training.
- Features used:
  - Packet size, flags, inter-arrival time, protocol, source/destination IPs, port numbers, TCP window size etc.

## Approach (Flowchart)

![image](https://github.com/user-attachments/assets/c7bd305e-b479-4875-af9c-9af64baa2bf4)


## Working of the Project

1. **Live Packet Capture & Feature Extraction**:
   
   - We used the Scapy library in Python to sniff live network packets from interfaces such as eth0 or wlan0.
   -  These extracted features are stored in a structured format (network_data.csv) for:
     
      - Feeding into the ML models for detection
      - Record-keeping and analysis
        
   - The system supports continuous packet capture, and users can terminate it anytime using CTRL+C.
     

![image](https://github.com/user-attachments/assets/db7dcb07-1cdd-4171-ac80-a40a61073b62)


2. **Random Forest-based Static Intrusion Detection**:
   
   - A Random Forest classifier was trained using historical network traffic data (labelled as normal or various attack types).
   - Model is trained on time-series data enabling it to:
     
     - Brute Force Attack
     - SYN Flood Attack
     - ARP Attack
    
   - The model outputs a prediction for each packet (e.g., normal or intrusion).
   - After training, the model is saved in .pkl format (random_forest_model.pkl) using  pickle.

3. **LSTM-based Dynamic Anomaly Detection**:
   
   - Built an LSTM (Long Short-Term Memory) neural network using PyTorch to detect anomalies in network behavior over time.
   - Model is trained on time-series data enabling it to:
     
     - Spot slow and stealthy attacks
     - Detect sudden abnormal spikes or traffic patterns

   - Training progress was logged per epoch. We can see:

     - Epoch 1, Loss: 0.681
     - Epoch 10, Loss: 0.685
    
  - After training, the model was saved as a PyTorch file (lstm_model.pth), ready for real-time inference.
    

![image](https://github.com/user-attachments/assets/d2d31fc5-b7ef-40fc-93b5-40575fd9e412)


4. **Real-Time Monitoring & Visualization**:
   - Used matplotlib.animation.FuncAnimation to create a live updating dashboard GUI in the terminal .
   - Model is trained on time-series data enabling it to:
  
     - Latency (Packets)
     - Upload/Download speeds (Bytes/sec)
     - Network usage trends
     - Forecasts via LSTM predictions
       
   - The dashboard updates every second (interval=1000 ms), giving the user a real-time view of the network status.
     

![image](https://github.com/user-attachments/assets/a0761607-95e4-499a-b01c-7e8a7b53dda3)


5. **Alert System & Logging Mechanism**:
   - An automated alert system is integrated using Microsoft Teams Webhooks.
   - When an anomaly is detected (by either the Random Forest or LSTM model), a real-time alert message is sent directly to a designated Teams channel.
   - The alert includes:
  
     - 📅 Timestamp of detection
     - 🌐 Source & Destination IPs
     - 🚨 Type of anomaly (e.g., Brute, Syn Flood attacks, etc)
       
    
![image](https://github.com/user-attachments/assets/80a574fd-378b-40b1-9762-61687c8a362b)

## Demo

https://github.com/user-attachments/assets/d0b232f9-9ede-4788-8ebf-e0d91e6548d9



## Contact
If you have any questions or suggestions, feel free to open an issue or contact:
Dhrishita Parve: dhrishitap18@gmail.com


