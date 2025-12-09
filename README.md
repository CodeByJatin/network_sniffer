# Network Traffic Analyzer Pro

A real-time network packet capture and analysis tool with a sleek dark-themed GUI.

## Features

- **Live Packet Capture** – Monitor network traffic in real-time using Scapy
- **Top Talkers** – Identify the top 3 IPs consuming the most bandwidth
- **Real-time Graphs** – Visualize packet rate (PPS) and throughput (KB/s)
- **BPF Filtering** – Apply Berkeley Packet Filter expressions to focus on specific traffic
- **PCAP Export** – Optionally save captures to disk for later analysis
- **Dark Theme** – Professional dark UI optimized for extended monitoring sessions

## Requirements

```
Python 3.7+
PySide6
pyqtgraph
scapy
```

## Installation

```bash
pip install PySide6 pyqtgraph scapy
```

**Note:** On Windows, you may need to install [Npcap](https://npcap.com/) for packet capture.

## Usage

```bash
python network_analyzer.py
```

1. Select a network interface from the dropdown
2. Optionally add a BPF filter (e.g., `tcp port 443`)
3. Enable "Save to .pcap" if you want to record the session
4. Click **Start Capture** to begin monitoring
5. Click **Stop** when finished

## Interface Overview

- **Dashboard Cards** – Total packets, data volume, current PPS and throughput
- **Live Graphs** – Smoothed time-series visualization of network activity
- **Top Talkers Table** – The 3 IPs with highest bandwidth usage
- **Packet Log** – Scrolling feed of captured packet summaries

## Notes

- Requires administrator/root privileges for packet capture
- Uses multiprocessing to separate capture from GUI rendering
- Graphs support auto-fit and manual smoothing toggle

---

*Built with PySide6, PyQtGraph, and Scapy*
