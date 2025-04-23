#!/usr/bin/env python3
import os
import sys
import time
from datetime import datetime
from collections import defaultdict, deque
import psutil
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.text import Text
from rich.box import ROUNDED
import questionary
from questionary import Style as QStyle

# Initialize console
console = Console()

# Custom questionary style
custom_style = QStyle([
    ('qmark', 'fg:#FF9D00 bold'),
    ('question', 'fg:#FFFFFF bold'),
    ('answer', 'fg:#5F87FF bold'),
    ('pointer', 'fg:#5F87FF bold'),
    ('selected', 'fg:#5F87FF'),
    ('separator', 'fg:#6C6C6C'),
    ('instruction', 'fg:#969696'),
    ('text', 'fg:#FFFFFF'),
])

class TrafficMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.stats = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'start_time': time.time(),
            'bandwidth': 0,
            'packet_history': deque(maxlen=50)  # Store last 50 packets
        }

    def update_stats(self, packet):
        try:
            self.stats['total_packets'] += 1
            packet_size = len(packet)
            self.stats['bandwidth'] += packet_size

            # Protocol detection
            proto = 'Other'
            src_port = ''
            dst_port = ''
            flags = ''
            info = ''

            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                if packet.haslayer(TCP):
                    proto = 'TCP'
                    src_port = str(packet[TCP].sport)
                    dst_port = str(packet[TCP].dport)
                    flags = str(packet[TCP].flags)
                    info = f"TCP {flags}"
                elif packet.haslayer(UDP):
                    proto = 'UDP'
                    src_port = str(packet[UDP].sport)
                    dst_port = str(packet[UDP].dport)
                    info = "UDP"
                elif packet.haslayer(ICMP):
                    proto = 'ICMP'
                    info = "ICMP"

                self.stats['protocols'][proto] += 1

                # Store packet details
                packet_info = {
                    'time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
                    'source': f"{src_ip}:{src_port}",
                    'destination': f"{dst_ip}:{dst_port}",
                    'protocol': proto,
                    'length': str(packet_size),
                    'info': info
                }
                self.stats['packet_history'].appendleft(packet_info)  # Newest first

        except Exception as e:
            console.print(f"[yellow]Packet processing error: {e}[/yellow]")

def get_network_interfaces():
    """Get available network interfaces"""
    try:
        interfaces = psutil.net_if_addrs().keys()
        return [iface for iface in interfaces if iface != 'lo']
    except Exception as e:
        console.print(f"[red]Error getting interfaces: {e}[/red]")
        return []

def verify_interface(interface):
    """Verify the interface exists and is up"""
    try:
        addrs = psutil.net_if_addrs().get(interface, [])
        return len(addrs) > 0
    except Exception:
        return False

def display_traffic(monitor):
    """Display the traffic dashboard"""
    # Create packet table
    packet_table = Table(title=f"Live Traffic on {monitor.interface}", box=ROUNDED)
    packet_table.add_column("No.", style="dim", width=5)
    packet_table.add_column("Time", style="bright_black", width=12)
    packet_table.add_column("Source", style="cyan", min_width=20)
    packet_table.add_column("→", style="dim", width=2)
    packet_table.add_column("Destination", style="magenta", min_width=20)
    packet_table.add_column("Protocol", style="green", width=8)
    packet_table.add_column("Length", style="yellow", width=8)
    packet_table.add_column("Info", style="white")

    # Add packets (newest first)
    for i, packet in enumerate(monitor.stats['packet_history']):
        packet_table.add_row(
            str(i+1),
            packet['time'],
            packet['source'],
            "→",
            packet['destination'],
            packet['protocol'],
            packet['length'],
            packet['info']
        )

    # Summary panel
    summary_panel = Table.grid()
    summary_panel.add_row(
        f"[b]Packets:[/b] {monitor.stats['total_packets']}",
        f"[b]Duration:[/b] {time.time() - monitor.stats['start_time']:.1f}s",
        f"[b]Bandwidth:[/b] {monitor.stats['bandwidth']/1024:.1f} KB"
    )

    # Combine everything
    layout = Table.grid()
    layout.add_row(summary_panel)
    layout.add_row(packet_table)
    
    return layout

def run_traffic_monitor(interface, duration):
    """Run the actual traffic monitoring"""
    if not verify_interface(interface):
        console.print(f"[red]Interface {interface} not found or not up![/red]")
        console.print("Available interfaces:")
        for iface in get_network_interfaces():
            console.print(f"- {iface}")
        return

    monitor = TrafficMonitor(interface)
    
    try:
        console.print(f"\n[green]Starting capture on {interface} for {duration} seconds...[/green]")
        console.print("[yellow]Press Ctrl+C to stop early[/yellow]")

        with Live(display_traffic(monitor), refresh_per_second=4, screen=True) as live:
            sniff(
                iface=interface,
                prn=lambda p: (monitor.update_stats(p), live.update(display_traffic(monitor))),
                timeout=int(duration),
                store=False
            )

    except PermissionError:
        console.print("\n[red]Permission denied! Try with:[/red]")
        console.print(f"[bold]sudo python3 {__file__} --traffic {interface} {duration}[/bold]")
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}[/red]")
    finally:
        console.print("\n[green]Capture completed![/green]")
        console.print(f"Total packets: {monitor.stats['total_packets']}")

def launch_traffic_monitor():
    """Main traffic monitor interface"""
    try:
        interfaces = get_network_interfaces()
        if not interfaces:
            console.print("[red]No network interfaces found![/red]")
            console.print("[yellow]Check your network connections and try again[/yellow]")
            return

        iface = questionary.select(
            "Select interface to monitor:",
            choices=interfaces,
            default="wlan0" if "wlan0" in interfaces else interfaces[0],
            style=custom_style
        ).ask()

        duration = questionary.text(
            "Monitoring duration (seconds):",
            default="60",
            validate=lambda x: x.isdigit() and int(x) > 0,
            style=custom_style
        ).ask()

        # Verify interface again
        if not verify_interface(iface):
            console.print(f"[red]Interface {iface} is not available![/red]")
            return

        # Check privileges
        if os.geteuid() != 0:
            console.print("\n[red]Traffic monitoring requires root privileges[/red]")
            if questionary.confirm("Run with sudo?", default=True).ask():
                os.execvp('sudo', ['sudo', sys.executable, __file__, '--traffic', iface, duration])
            return
        
        
        # Check for alerts
            for alert_name, condition in Config.ALERTS.items():
                if condition(packet):
                    self.stats['alerts'][alert_name] += 1
                    color = 'red'
                    info = f"ALERT: {alert_name} - {info}"
        
        # Run the monitor
        run_traffic_monitor(iface, duration)

    except KeyboardInterrupt:
        console.print("\n[red]Operation cancelled by user[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--traffic":
        # Direct traffic capture mode
        if len(sys.argv) < 4:
            console.print("[red]Usage: sudo python3 shadownet.py --traffic <interface> <duration>[/red]")
            sys.exit(1)
        run_traffic_monitor(sys.argv[2], sys.argv[3])
    else:
        # Normal interactive mode
        launch_traffic_monitor()