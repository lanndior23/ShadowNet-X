# core/monitor/traffic_monitor.py
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import threading
from rich.live import Live
from rich.table import Table
from rich.console import Console
import time
import os
import sys

console = Console()

class TrafficMonitor:
    def __init__(self, iface="eth0", filter_expr="", max_packets=0):
        self.iface = iface
        self.filter_expr = filter_expr
        self.max_packets = max_packets
        self.packet_stats = defaultdict(lambda: defaultdict(int))
        self.running = False

    def _process_packet(self, packet):
        if IP in packet:
            proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "Other"
            src = packet[IP].src
            dst = packet[IP].dst
            self.packet_stats[proto]["count"] += 1
            self.packet_stats[proto]["bytes"] += len(packet)
            self.packet_stats[proto]["flows"].add((src, dst))

    def _sniff_packets(self):
        try:
            console.print(f"[bold cyan]Sniffing on interface:[/bold cyan] {self.iface}")
            sniff(
                iface=self.iface,
                filter=self.filter_expr,
                prn=self._process_packet,
                store=False,
                count=self.max_packets
            )
        except PermissionError:
            console.print("[bold red]Error:[/bold red] Permission denied. Try running the script as root or with sudo.")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]Sniffing failed:[/bold red] {e}")
            console.print("[yellow]Falling back to default interface...[/yellow]")
            try:
                sniff(
                    prn=self._process_packet,
                    store=False,
                    count=self.max_packets
                )
            except Exception as fallback_error:
                console.print(f"[bold red]Fallback also failed:[/bold red] {fallback_error}")
                sys.exit(1)

    def start_monitoring(self, duration=30):
        self.running = True
        for proto in ["TCP", "UDP", "ICMP", "Other"]:
            self.packet_stats[proto]["count"] = 0
            self.packet_stats[proto]["bytes"] = 0
            self.packet_stats[proto]["flows"] = set()

        sniffer_thread = threading.Thread(target=self._sniff_packets)
        sniffer_thread.start()

        with Live(self._render_table(), refresh_per_second=2) as live:
            start_time = time.time()
            while self.running and (time.time() - start_time < duration):
                live.update(self._render_table())
                time.sleep(1)
            self.running = False

    def _render_table(self):
        table = Table(title="Traffic Monitor", show_header=True, header_style="bold magenta")
        table.add_column("Protocol", justify="center")
        table.add_column("Packets", justify="right")
        table.add_column("Bytes", justify="right")
        table.add_column("Unique Flows", justify="right")
        for proto, stats in self.packet_stats.items():
            table.add_row(
                proto,
                str(stats["count"]),
                str(stats["bytes"]),
                str(len(stats["flows"]))
            )
        return table
