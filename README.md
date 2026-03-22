# Light-IDS

LightIDS is a lightweight network intrusion detection system (NIDS) built for educational and portfolio purposes.  
It captures and analyses network traffic in real time or from PCAP files, applies rule-based detection logic, logs structured alerts, and visualises attack activity through a dashboard.

The project was designed to demonstrate practical understanding of packet capture, TCP/IP analysis, rule-based anomaly detection, and security analytics workflow.

---

## Features

- Live packet capture using Scapy
- Offline PCAP analysis
- TCP/UDP packet parsing
- Rule-based intrusion detection for:
  - Port scanning
  - SYN-heavy anomalies
  - Brute-force style repeated access
- Alert cooldown / deduplication
- Structured JSONL alert logging
- Dashboard for visualising:
  - Total alerts
  - Severity distribution
  - Attack type distribution
  - Attack timeline
  - Top attackers
  - Recent alerts

---

## Architecture

LightIDS follows a simple pipeline:

```text
Packet Source (Live / PCAP)
        ↓
Packet Parser
        ↓
Detection Engine
        ↓
Alert Logger (JSONL)
        ↓
Backend API
        ↓
Dashboard UI

```

# Core modules

- Capture Layer: collects packets from live traffic or PCAP files
  -Parser Layer: extracts key fields such as source IP, destination port, protocol, and TCP flags
  -Detection Layer: applies rule-based logic to identify suspicious behaviour
  -Logging Layer: writes alerts into JSONL format for analytics
  -Dashboard Layer: displays security metrics and trends

```

# Detection Logic
1. Port Scan Detection

Detects when the same source IP accesses many unique destination ports within a short time window.

Example rule
-10 unique destination ports within 10 seconds → raise PORT_SCAN
-2. SYN Anomaly Detection

Detects TCP traffic with many SYN packets but very few ACK packets, which may indicate SYN scan or SYN flood behaviour.

Example rule
-At least 20 SYN packets within 10 seconds
-ACK / SYN ratio below 0.2
-Raise SYN_ANOMALY

3. Brute Force Detection

Detects repeated connections from the same source IP to the same sensitive service port.

Monitored ports

21 (FTP)
22 (SSH)
23 (Telnet)
3389 (RDP)

Example rule
-15 repeated attempts to the same sensitive port within 30 seconds → raise BRUTE_FORCE
```

# Tech Stack

Backend / Detection
Python 3
Scapy
argparse
JSON / JSONL logging
Dashboard API
Node.js
Express
CORS
Frontend
HTML
CSS
JavaScript
Chart.js

# Why JSONL Instead of JSON?

JSONL was used because this project produces alerts as a stream of events.

# Advantages:

-append-only writes
-efficient logging
-fault-tolerant for long-running processes
-easier integration with analytics pipelines

Each line is a standalone JSON record, making it suitable for real-time IDS logging.

# Limitations

-Rule-based only; no machine learning detection
-Simplified TCP behaviour analysis
-SYN anomaly detection does not fully reconstruct TCP state
-May generate false positives in high-frequency legitimate traffic
-Dashboard currently focuses on overview analytics rather than deep forensic drill-down

# Future Improvements

-Add filtering by alert type and severity
-Add threat summary / explanation panel
-Implement stateful TCP tracking
-Add support for more protocols and richer payload inspection
-Introduce multiple attacker simulation for richer analytics
-Export alerts to SIEM-compatible pipelines

# Project Purpose

This project was built to demonstrate:
-practical network security engineering
-understanding of packet-level traffic analysis
-rule-based intrusion detection design
-security logging and analytics workflow
-full-stack integration from detection engine to dashboard

# Dashboard Screenshots

<img src='/screenshots/dashboard1.png'>
<img src='/screenshots/dashboard2.png'
