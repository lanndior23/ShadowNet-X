from collections import defaultdict
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP

class TrafficEngine:
    def __init__(self):
        self.stats = {
            'protocols': defaultdict(int),
            'threats': [],
            'talkers': defaultdict(lambda: {'packets': 0, 'bytes': 0}),
            'packets': []
        }
        self.running = False
        
    def process_packet(self, packet):
        """Shared packet processing logic"""
        if IP in packet:
            # Extract common information
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)
            
            # Protocol detection
            protocol = "Other"
            if TCP in packet:
                protocol = "TCP"
                self._check_tcp_threats(packet)
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            
            # Update statistics
            self.stats['protocols'][protocol] += 1
            self.stats['talkers'][src_ip]['packets'] += 1
            self.stats['talkers'][src_ip]['bytes'] += length
            self.stats['packets'].append((time.time(), src_ip, dst_ip, protocol, length, packet.summary()))
    
    def _check_tcp_threats(self, packet):
        """Threat detection logic"""
        if packet[TCP].flags == 2:  # SYN scan detection
            self.stats['threats'].append((
                time.time(),
                "Port Scan",
                packet[IP].src,
                f"Targeting port {packet[TCP].dport}"
            ))