import random
import time
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP, fragment
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from typing import Optional, Union, List, Tuple
import logging
from dataclasses import dataclass
import socket
import ipaddress
from multiprocessing import Pool

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class EvasionConfig:
    """Configuration for evasion techniques"""
    max_delay: float = 3.0
    min_delay: float = 0.5
    fragment_threshold: int = 8  # MTU fragmentation threshold
    decoy_count: int = 3
    source_port: int = random.randint(1024, 65535)
    ttl_variation: bool = True
    randomize_ids: bool = True
    use_ipv6: bool = False
    spoof_mac: bool = False

class EvasionEngine:
    def __init__(self, config: Optional[EvasionConfig] = None):
        """
        Initialize the evasion engine with optional configuration.
        
        Args:
            config: Evasion configuration parameters
        """
        self.config = config if config else EvasionConfig()
        self._validate_config()
        
        # Pre-compute decoy IPs
        self._decoy_ips = self._generate_decoy_ips(self.config.decoy_count)
        
        logger.info("EvasionEngine initialized with configuration: %s", self.config)

    def _validate_config(self):
        """Validate evasion configuration parameters."""
        if self.config.min_delay < 0:
            raise ValueError("Minimum delay must be >= 0")
        if self.config.max_delay < self.config.min_delay:
            raise ValueError("Max delay must be >= min delay")
        if self.config.fragment_threshold < 1:
            raise ValueError("Fragment threshold must be >= 1")
        if self.config.decoy_count < 0:
            raise ValueError("Decoy count must be >= 0")

    def _generate_decoy_ips(self, count: int) -> List[str]:
        """Generate random decoy IP addresses."""
        return [f"{random.randint(1,255)}.{random.randint(1,255)}."
                f"{random.randint(1,255)}.{random.randint(1,255)}" 
                for _ in range(count)]

    def timing_evasion(self, jitter: bool = True) -> None:
        """
        Introduce random delays with optional jitter pattern.
        
        Args:
            jitter: Whether to use non-uniform timing patterns
        """
        if jitter:
            # Use a more sophisticated jitter pattern
            delay = random.betavariate(2, 5) * self.config.max_delay
            delay = max(min(delay, self.config.max_delay), self.config.min_delay)
        else:
            delay = random.uniform(self.config.min_delay, self.config.max_delay)
            
        logger.debug(f"Applying timing evasion: sleeping for {delay:.2f}s")
        time.sleep(delay)

    def packet_fragmentation(self, 
                           target_ip: str, 
                           port: int, 
                           protocol: str = "tcp",
                           flags: str = "S") -> List[scapy.Packet]:
        """
        Advanced packet fragmentation with multiple techniques.
        
        Args:
            target_ip: Target IP address
            port: Target port
            protocol: 'tcp', 'udp', or 'icmp'
            flags: TCP flags (if protocol is TCP)
            
        Returns:
            List of fragmented packets
        """
        # Create base packet
        if protocol.lower() == "tcp":
            pkt = IP(dst=target_ip)/TCP(dport=port, flags=flags)
        elif protocol.lower() == "udp":
            pkt = IP(dst=target_ip)/UDP(dport=port)
        elif protocol.lower() == "icmp":
            pkt = IP(dst=target_ip)/ICMP()
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")
            
        # Apply evasion techniques
        pkt = self._apply_evasion_techniques(pkt)
        
        # Fragment the packet
        fragments = fragment(pkt, fragsize=self.config.fragment_threshold)
        logger.debug(f"Fragmented packet into {len(fragments)} fragments")
        
        return fragments

    def _apply_evasion_techniques(self, packet: scapy.Packet) -> scapy.Packet:
        """Apply multiple evasion techniques to a packet."""
        # Randomize IP identification field
        if self.config.randomize_ids:
            packet[IP].id = random.randint(1, 65535)
            
        # Vary TTL
        if self.config.ttl_variation:
            packet[IP].ttl = random.choice([32, 64, 128, 255])
            
        # Randomize source port for TCP/UDP
        if TCP in packet or UDP in packet:
            packet[TCP if TCP in packet else UDP].sport = random.randint(1024, 65535)
            
        return packet

    def decoy_scan(self, 
                  target_ip: str, 
                  port: int, 
                  real_ip: Optional[str] = None) -> None:
        """
        Perform a decoy scan with spoofed source IPs.
        
        Args:
            target_ip: Target IP address
            port: Target port
            real_ip: Your real IP to mix with decoys (optional)
        """
        all_ips = self._decoy_ips.copy()
        if real_ip:
            all_ips.append(real_ip)
            
        random.shuffle(all_ips)
        
        logger.info(f"Performing decoy scan with {len(all_ips)} spoofed sources")
        
        for ip in all_ips:
            pkt = IP(src=ip, dst=target_ip)/TCP(dport=port, flags="S")
            pkt = self._apply_evasion_techniques(pkt)
            scapy.send(pkt, verbose=False)
            self.timing_evasion()

    def dns_tunneling_attempt(self,
                            target_ip: str,
                            domain: str = "example.com",
                            query_type: str = "A") -> None:
        """
        Attempt DNS tunneling evasion by hiding data in DNS queries.
        
        Args:
            target_ip: DNS server IP
            domain: Domain to query
            query_type: DNS query type (A, AAAA, TXT, etc.)
        """
        try:
            # Create DNS query with random subdomain
            subdomain = f"{random.randint(1,1000000)}.data.{domain}"
            pkt = IP(dst=target_ip)/UDP()/DNS(rd=1, qd=DNSQR(qname=subdomain, qtype=query_type))
            
            # Fragment and send
            fragments = fragment(pkt, fragsize=self.config.fragment_threshold)
            for frag in fragments:
                scapy.send(frag, verbose=False)
                self.timing_evasion(jitter=True)
                
            logger.debug(f"Sent DNS tunneling attempt for {subdomain}")
        except Exception as e:
            logger.error(f"DNS tunneling attempt failed: {e}")

    def http_header_manipulation(self,
                               target_ip: str,
                               port: int = 80,
                               method: str = "GET",
                               path: str = "/") -> None:
        """
        Evade WAFs/IDS by manipulating HTTP headers.
        
        Args:
            target_ip: Target web server
            port: Target port
            method: HTTP method
            path: Request path
        """
        try:
            # Create HTTP request with evasion headers
            headers = [
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                "X-Forwarded-For: " + self._decoy_ips[0],
                "Accept: */*",
                "Accept-Encoding: " + ",".join(["gzip", "deflate", "br", ""]),
                "Cache-Control: " + random.choice(["no-cache", "max-age=0", ""]),
                "Connection: " + random.choice(["keep-alive", "close", "upgrade"])
            ]
            
            # Randomize header order
            random.shuffle(headers)
            
            # Build request
            request = f"{method} {path} HTTP/1.1\r\nHost: {target_ip}\r\n"
            request += "\r\n".join(headers) + "\r\n\r\n"
            
            # Send through TCP
            pkt = IP(dst=target_ip)/TCP(dport=port, flags="PA")/Raw(load=request)
            pkt = self._apply_evasion_techniques(pkt)
            scapy.send(pkt, verbose=False)
            
            logger.debug(f"Sent HTTP request with evasive headers to {target_ip}")
        except Exception as e:
            logger.error(f"HTTP header manipulation failed: {e}")

    def tcp_flag_manipulation(self,
                             target_ip: str,
                             port: int,
                             flags: Union[str, int] = "SA",
                             bad_checksum: bool = True) -> None:
        """
        Send packets with unusual TCP flag combinations.
        
        Args:
            target_ip: Target IP
            port: Target port
            flags: TCP flags (string like "SA" or integer)
            bad_checksum: Whether to use invalid checksum
        """
        try:
            if isinstance(flags, str):
                # Convert flag string to numerical value
                flag_val = 0
                if "F" in flags: flag_val |= 0x01
                if "S" in flags: flag_val |= 0x02
                if "R" in flags: flag_val |= 0x04
                if "P" in flags: flag_val |= 0x08
                if "A" in flags: flag_val |= 0x10
                if "U" in flags: flag_val |= 0x20
                flags = flag_val
                
            pkt = IP(dst=target_ip)/TCP(dport=port, flags=flags)
            
            if bad_checksum:
                pkt[TCP].chksum = random.randint(0, 65535)
                
            pkt = self._apply_evasion_techniques(pkt)
            scapy.send(pkt, verbose=False)
            
            logger.debug(f"Sent TCP packet with unusual flags {bin(flags)} to {target_ip}:{port}")
        except Exception as e:
            logger.error(f"TCP flag manipulation failed: {e}")

    def parallel_evasion_scan(self,
                            target_ip: str,
                            ports: List[int],
                            techniques: List[str] = ["fragment", "timing", "ttl"]) -> Dict[int, str]:
        """
        Perform a scan using multiple evasion techniques in parallel.
        
        Args:
            target_ip: Target IP address
            ports: List of ports to scan
            techniques: List of evasion techniques to use
            
        Returns:
            Dictionary of port to technique used
        """
        results = {}
        
        with Pool(processes=min(len(ports), 10)) as pool:
            args = [(target_ip, port, techniques) for port in ports]
            scan_results = pool.starmap(self._single_port_scan, args)
            
        for port, result in zip(ports, scan_results):
            results[port] = result
            
        return results

    def _single_port_scan(self,
                        target_ip: str,
                        port: int,
                        techniques: List[str]) -> str:
        """
        Scan a single port with selected evasion techniques.
        
        Args:
            target_ip: Target IP
            port: Target port
            techniques: List of evasion techniques
            
        Returns:
            Technique used for this port
        """
        technique = random.choice(techniques)
        
        try:
            if technique == "fragment":
                fragments = self.packet_fragmentation(target_ip, port)
                for frag in fragments:
                    scapy.send(frag, verbose=False)
            elif technique == "timing":
                self.timing_evasion(jitter=True)
                scapy.send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=False)
            elif technique == "ttl":
                pkt = IP(dst=target_ip, ttl=random.choice([32, 64, 128]))/TCP(dport=port, flags="S")
                scapy.send(pkt, verbose=False)
            elif technique == "decoy":
                self.decoy_scan(target_ip, port)
                
            logger.debug(f"Scanned {target_ip}:{port} using {technique} evasion")
            return technique
        except Exception as e:
            logger.error(f"Failed to scan {target_ip}:{port} with {technique}: {e}")
            return "failed"