import sys
import time
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
import pyqtgraph as pg
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP
import threading
from collections import defaultdict

# ========== DARK THEME & HACKER STYLE ========== #
pg.setConfigOption('background', '#0a0a0a')
pg.setConfigOption('foreground', '#00ff00')

class HackerTrafficDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ShadowNet-X // Traffic Monitor [ADMIN]")
        self.setGeometry(100, 100, 1200, 800)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0a0a0a;
                color: #00ff00;
                font-family: 'Courier New';
            }
            QLabel {
                color: #00ff00;
            }
            QPushButton {
                background-color: #003300;
                color: #00ff00;
                border: 1px solid #00aa00;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: #005500;
            }
            QTableWidget {
                background-color: #111111;
                color: #00ff00;
                gridline-color: #003300;
            }
            QHeaderView::section {
                background-color: #002200;
                color: #00ff00;
            }
            QTabWidget::pane {
                border: 1px solid #00aa00;
            }
            QTabBar::tab {
                background: #002200;
                color: #00ff00;
                padding: 8px;
            }
            QTabBar::tab:selected {
                background: #005500;
            }
        """)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QHBoxLayout(self.central_widget)

        # ===== LEFT PANEL (Traffic Stats) ===== #
        self.left_panel = QVBoxLayout()
        
        # --- Real-time Bandwidth Graph --- #
        self.graph_widget = pg.PlotWidget(title="<span style='color: #00ff00'>Bandwidth Usage (Mbps)</span>")
        self.graph_widget.setLabel('left', 'Mbps')
        self.graph_widget.setLabel('bottom', 'Time (s)')
        self.graph_curve = self.graph_widget.plot(pen=pg.mkPen('#00ff00', width=2))
        self.left_panel.addWidget(self.graph_widget)

        # --- Protocol Distribution Pie Chart --- #
        self.pie_chart = pg.PlotWidget(title="<span style='color: #00ff00'>Protocol Distribution</span>")
        self.pie = pg.PieChart()
        self.pie_chart.addItem(self.pie)
        self.left_panel.addWidget(self.pie_chart)

        # ===== RIGHT PANEL (Analytics & Alerts) ===== #
        self.right_panel = QTabWidget()
        
        # --- Tab 1: Packet Log --- #
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length", "Info"])
        self.right_panel.addTab(self.packet_table, "Packet Log")

        # --- Tab 2: Threat Alerts --- #
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(4)
        self.threat_table.setHorizontalHeaderLabels(["Time", "Threat Type", "Source IP", "Action"])
        self.right_panel.addTab(self.threat_table, "Threat Alerts")

        # --- Tab 3: Top Talkers --- #
        self.talkers_table = QTableWidget()
        self.talkers_table.setColumnCount(3)
        self.talkers_table.setHorizontalHeaderLabels(["IP", "Packets", "Data (KB)"])
        self.right_panel.addTab(self.talkers_table, "Top Talkers")

        # ===== BOTTOM CONTROLS ===== #
        self.controls = QHBoxLayout()
        self.start_btn = QPushButton("▶ Start Sniffing")
        self.stop_btn = QPushButton("⏹ Stop")
        self.filter_input = QLineEdit(placeholderText="Filter (e.g., 'tcp port 80')")
        self.export_btn = QPushButton("💾 Export PCAP")
        
        self.controls.addWidget(self.start_btn)
        self.controls.addWidget(self.stop_btn)
        self.controls.addWidget(self.filter_input)
        self.controls.addWidget(self.export_btn)

        # ===== FINAL LAYOUT ===== #
        self.layout.addLayout(self.left_panel, 60)
        self.layout.addWidget(self.right_panel, 40)
        self.layout.addLayout(self.controls)

        # ===== DATA & THREADING ===== #
        self.packets = []
        self.running = False
        self.sniffer_thread = None
        self.protocol_stats = defaultdict(int)
        self.threats = []
        self.talkers = defaultdict(lambda: {"packets": 0, "bytes": 0})

        # ===== CONNECT BUTTONS ===== #
        self.start_btn.clicked.connect(self.start_sniffing)
        self.stop_btn.clicked.connect(self.stop_sniffing)
        self.export_btn.clicked.connect(self.export_pcap)

        # ===== TIMER FOR LIVE UPDATES ===== #
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_dashboard)
        self.timer.start(1000)  # Update every 1s

    def start_sniffing(self):
        if not self.running:
            self.running = True
            self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
            self.sniffer_thread.start()
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)

    def stop_sniffing(self):
        self.running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def sniff_packets(self):
        filter_text = self.filter_input.text() or None
        sniff(prn=self.process_packet, filter=filter_text, store=False, stop_filter=lambda _: not self.running)

    def process_packet(self, packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            length = len(packet)
            
            # Update protocol stats
            if TCP in packet:
                protocol = "TCP"
            elif UDP in packet:
                protocol = "UDP"
            elif ICMP in packet:
                protocol = "ICMP"
            else:
                protocol = "Other"
            
            self.protocol_stats[protocol] += 1
            
            # Update top talkers
            self.talkers[src_ip]["packets"] += 1
            self.talkers[src_ip]["bytes"] += length
            
            # Detect threats (example: port scan)
            if TCP in packet and packet[TCP].flags == 2:  # SYN scan
                self.threats.append(("Port Scan", src_ip, time.time()))
            
            # Add to packet log
            self.packets.append((time.time(), src_ip, dst_ip, protocol, length, packet.summary()))

    def update_dashboard(self):
        # Update Bandwidth Graph
        if len(self.packets) > 0:
            self.graph_curve.setData([p[0] for p in self.packets], [p[4] / 1000 for p in self.packets])  # KB/s
        
        # Update Protocol Pie Chart
        self.pie.setData(self.protocol_stats.values(), labels=self.protocol_stats.keys())
        
        # Update Packet Log
        self.packet_table.setRowCount(min(100, len(self.packets)))
        for i, p in enumerate(self.packets[-100:]):
            for j, val in enumerate(p):
                self.packet_table.setItem(i, j, QTableWidgetItem(str(val)))
        
        # Update Threat Alerts
        self.threat_table.setRowCount(len(self.threats))
        for i, threat in enumerate(self.threats):
            for j, val in enumerate(threat):
                self.threat_table.setItem(i, j, QTableWidgetItem(str(val)))
        
        # Update Top Talkers
        self.talkers_table.setRowCount(min(10, len(self.talkers)))
        sorted_talkers = sorted(self.talkers.items(), key=lambda x: x[1]["bytes"], reverse=True)
        for i, (ip, stats) in enumerate(sorted_talkers[:10]):
            self.talkers_table.setItem(i, 0, QTableWidgetItem(ip))
            self.talkers_table.setItem(i, 1, QTableWidgetItem(str(stats["packets"])))
            self.talkers_table.setItem(i, 2, QTableWidgetItem(str(stats["bytes"] / 1024)))

    def export_pcap(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getSaveFileName(self, "Save PCAP", "", "PCAP Files (*.pcap)", options=options)
        if file_name:
            # TODO: Save packets to PCAP
            QMessageBox.information(self, "Export", f"Saved to {file_name}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HackerTrafficDashboard()
    window.show()
    sys.exit(app.exec_())