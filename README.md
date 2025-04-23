# ShadowNet-X Traffic Monitor 🌐🔍


A real-time network traffic analyzer with Wireshark-like terminal interface, security alerts, and export capabilities.

## Features ✨

- 🕵️‍♂️ **Live Packet Inspection** - Color-coded TCP/UDP/ICMP/ARP/DNS traffic
- 🚨 **Security Alerts** - Detect port scans, suspicious DNS queries, and large transfers
- 📊 **Protocol Analytics** - Bandwidth usage and protocol distribution
- 💾 **Export Options** - Save captures as CSV or PCAP
- 🎨 **Rich Terminal UI** - Interactive dashboard with keyboard controls

## Installation ⚙️

### Requirements
```bash
# Linux (Kali/Ubuntu)
sudo apt install tcpdump python3-pip
Python Packages
bash
pip install -r requirements.txt
See requirements.txt for full dependencies

Usage 🖥️

# Run with sudo (required)
sudo python3 shadownet.py

Key Controls
Key	               Action
↑/↓	             Scroll packet list
Ctrl+C	           Stop capture
E	            Export current capture


Command Reference 📜
Command	                        Description
--interface eth0	       Specify network interface
--duration 60	          Set capture duration (seconds)
--filter "tcp port 80"	     Apply BPF filter
--export capture.pcap	    Auto-export to PCAP

Examples 🛠️
Basic Capture
sudo python3 shadownet.py --interface wlan0 --duration 120

HTTP Traffic Only
sudo python3 shadownet.py --filter "tcp port 80"

Capture with Auto-Export
sudo python3 shadownet.py --export http_capture.csv


Troubleshooting 🐛
Issue: No packets detected
✅ Verify interface: ip link show
✅ Test with: sudo tcpdump -i [INTERFACE] -c 5

Issue: Import errors
✅ Reinstall dependencies: pip install --force-reinstall -r requirements.txt


