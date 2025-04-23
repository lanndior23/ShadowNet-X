import scapy.all as scapy
from multiprocessing import Pool, cpu_count
import ipaddress
import socket
import time
from dataclasses import dataclass
from typing import List, Dict, Union, Optional
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class HostResult:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    open_ports: Optional[List[int]] = None
    os_fingerprint: Optional[str] = None

class NetworkScanner:
    def __init__(self, target: str, mode: str = "quick", threads: int = None, timeout: int = 2):
        """
        Initialize the network scanner.
        
        Args:
            target: IP address, range (CIDR notation), or hostname
            mode: "quick" (common ports), "full" (all ports), "syn" (stealth), or "udp" (UDP scan)
            threads: Number of parallel threads to use (default: CPU count * 2)
            timeout: Response timeout in seconds
        """
        self.target = self._validate_target(target)
        self.mode = mode.lower()
        self.timeout = timeout
        self.threads = threads if threads else cpu_count() * 2
        
        # Port configurations
        self.port_config = {
            "quick": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080],
            "full": list(range(1, 1025)) + [2049, 3306, 3389, 5432, 5900, 8080, 8443],
            "syn": [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080],  # Stealth SYN scan
            "udp": [53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514, 520],  # Common UDP ports
            "common": [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                      993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        }
        
        # Validate mode
        valid_modes = list(self.port_config.keys())
        if self.mode not in valid_modes:
            raise ValueError(
                f"Invalid mode '{mode}'. Must be one of: {valid_modes}\n"
                "Available scan types:\n"
                "  quick: Quick scan (common ports)\n"
                "  full: Full port scan (1-1024 + additional ports)\n"
                "  syn: Stealth SYN scan (requires root)\n"
                "  udp: UDP port scan\n"
                "  common: Most commonly used ports"
            )

    def _validate_target(self, target: str) -> str:
        """Validate and normalize the target input."""
        try:
            # Check if it's a CIDR range
            if '/' in target:
                ipaddress.ip_network(target, strict=False)
                return target
            # Check if it's a single IP
            else:
                ipaddress.ip_address(target)
                return target
        except ValueError:
            # Try to resolve hostname
            try:
                ip = socket.gethostbyname(target)
                return ip
            except socket.gaierror:
                raise ValueError(f"Invalid target: {target}. Must be IP, CIDR range, or resolvable hostname")

    def arp_scan(self) -> List[HostResult]:
        """Discover live hosts using ARP with additional host information."""
        logger.info(f"Starting ARP scan for target: {self.target}")
        
        arp = scapy.ARP(pdst=self.target)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        start_time = time.time()
        result = scapy.srp(packet, timeout=self.timeout, verbose=False)[0]
        
        hosts = []
        for sent, received in result:
            try:
                hostname = self._reverse_dns_lookup(received.psrc)
            except (socket.herror, socket.gaierror):
                hostname = None
                
            hosts.append(HostResult(
                ip=received.psrc,
                mac=received.hwsrc,
                hostname=hostname
            ))
        
        logger.info(f"ARP scan completed in {time.time() - start_time:.2f}s. Found {len(hosts)} hosts.")
        return hosts

    def _reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for an IP address."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror):
            return None

    def port_scan(self, ip: str) -> HostResult:
        """Perform TCP SYN scan on target IP with advanced features."""
        logger.info(f"Starting {self.mode} port scan for {ip}")
        
        open_ports = []
        start_time = time.time()
        
        # Use multiprocessing for faster scanning
        with Pool(processes=self.threads) as pool:
            results = pool.map(self._check_port, [(ip, port) for port in self.port_config[self.mode]])
        
        open_ports = [port for port, is_open in results if is_open]
        
        # Basic OS fingerprinting
        os_fingerprint = self._os_fingerprint(ip)
        
        logger.info(f"Port scan for {ip} completed in {time.time() - start_time:.2f}s. "
                   f"Found {len(open_ports)} open ports.")
        
        return HostResult(
            ip=ip,
            open_ports=open_ports,
            os_fingerprint=os_fingerprint
        )

    def _check_port(self, args: tuple) -> tuple:
        """Check if a port is open (SYN-ACK response)."""
        ip, port = args
        pkt = scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="S")
        resp = scapy.srp1(pkt, timeout=self.timeout, verbose=False)
        
        if resp and resp.haslayer(scapy.TCP):
            flags = resp.getlayer(scapy.TCP).flags
            if flags == 0x12:  # SYN-ACK
                # Send RST to close connection
                scapy.send(scapy.IP(dst=ip)/scapy.TCP(dport=port, flags="R"), verbose=False)
                return (port, True)
            elif flags == 0x14:  # RST-ACK
                return (port, False)
        return (port, False)

    def _os_fingerprint(self, ip: str) -> Optional[str]:
        """Basic OS fingerprinting using TCP/IP stack differences."""
        try:
            # Send TCP SYN to closed port
            pkt = scapy.IP(dst=ip)/scapy.TCP(dport=9999, flags="S")
            resp = scapy.srp1(pkt, timeout=self.timeout, verbose=False)
            
            if not resp or not resp.haslayer(scapy.TCP):
                return None
                
            # Analyze response characteristics
            ttl = resp.getlayer(scapy.IP).ttl
            window_size = resp.getlayer(scapy.TCP).window
            
            # Basic OS fingerprinting based on TTL and window size
            if ttl <= 64:
                if window_size == 5840:
                    return "Linux (kernel 2.4/2.6)"
                elif window_size == 5720:
                    return "Google Linux"
                elif window_size == 65535:
                    return "FreeBSD/MacOS"
                else:
                    return "Linux/Unix-like"
            elif ttl <= 128:
                if window_size == 8192:
                    return "Windows XP/7/10"
                else:
                    return "Windows"
            else:
                return "Unknown (TTL > 128)"
        except Exception as e:
            logger.warning(f"OS fingerprinting failed for {ip}: {str(e)}")
            return None

    def comprehensive_scan(self) -> List[HostResult]:
        """Perform a comprehensive scan (ARP discovery + port scanning)."""
        logger.info(f"Starting comprehensive network scan for {self.target}")
        
        # Discover hosts
        hosts = self.arp_scan()
        
        # Scan each host
        results = []
        with Pool(processes=min(self.threads, len(hosts))) as pool:
            results = pool.map(self.port_scan, [host.ip for host in hosts])
        
        # Merge results
        for host in hosts:
            for result in results:
                if host.ip == result.ip:
                    host.open_ports = result.open_ports
                    host.os_fingerprint = result.os_fingerprint
                    break
        
        return hosts