from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from .engine import TrafficEngine
import threading
import time

def run_cli_monitor(interface, duration):
    """Terminal-based traffic monitor"""
    engine = TrafficEngine()
    
    # Start sniffing thread
    sniff_thread = threading.Thread(
        target=sniff,
        kwargs={
            'prn': engine.process_packet,
            'iface': interface,
            'store': False
        },
        daemon=True
    )
    sniff_thread.start()
    
    # Display interface
    with Live(refresh_per_second=4) as live:
        start_time = time.time()
        while time.time() - start_time < duration:
            live.update(_build_cli_dashboard(engine.stats))
            time.sleep(0.25)

def _build_cli_dashboard(stats):
    """Build Rich CLI dashboard"""
    # Protocol table
    protocol_table = Table(title="Protocol Distribution")
    protocol_table.add_column("Protocol")
    protocol_table.add_column("Count")
    
    for proto, count in stats['protocols'].items():
        protocol_table.add_row(proto, str(count))
    
    # Threat panel
    threat_panel = Panel(
        "\n".join(f"{t[1]} from {t[2]}" for t in stats['threats'][-5:]),
        title="Threat Alerts"
    )
    
    return Panel(Group(protocol_table, threat_panel), title="Traffic Monitor")