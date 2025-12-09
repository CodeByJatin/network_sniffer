import sys
import time
import os
from datetime import datetime
from collections import deque, defaultdict
from multiprocessing import Process, Queue, Event
import queue as py_queue

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QTextEdit, QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QSplitter, QGroupBox, QStyleFactory, QCheckBox
)
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QFont, QColor, QPalette

import pyqtgraph as pg
from scapy.all import sniff, TCP, UDP, ICMP, IP
from scapy.utils import PcapWriter
from scapy.arch.windows import get_windows_if_list

# Constants & Configuration 
UI_UPDATE_INTERVAL_MS = 100 
GRAPH_HISTORY_SIZE = 120

# 1. The Sniffer Process 
def run_sniffer_process(iface, cap_filter, data_queue, stop_event, pcap_filename):
    """
    Runs in a separate process. 
    """
    pcap_writer = None
    if pcap_filename:
        try:
            pcap_writer = PcapWriter(pcap_filename, append=True, sync=True)
        except Exception as e:
            data_queue.put(("ERROR", f"Could not open PCAP file: {e}"))

    def packet_callback(pkt):
        if stop_event.is_set():
            return

        try:
            # A. Save to Disk (PCAP)
            if pcap_writer:
                pcap_writer.write(pkt)

            # B. Extract Stats for GUI 
            ts = time.time()
            pkt_len = len(pkt)
            
            # Basic Extraction
            proto = "Other"
            src_ip = None
            dst_ip = None
            
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                
                if TCP in pkt:
                    proto = "TCP"
                elif UDP in pkt:
                    proto = "UDP"
                elif ICMP in pkt:
                    proto = "ICMP"
                else:
                    proto = "IP"

            # Summary (Limited length to save IPC bandwidth)
            summary = pkt.summary()[:100]

            # Pack data into a tuple 
            packet_data = (ts, pkt_len, proto, src_ip, dst_ip, summary)
            
            data_queue.put(packet_data)
            
        except Exception:
            pass

    try:
        sniff(
            iface=iface, 
            filter=cap_filter, 
            prn=packet_callback, 
            store=False, 
            stop_filter=lambda x: stop_event.is_set()
        )
    except Exception as e:
        data_queue.put(("ERROR", str(e)))
    finally:
        if pcap_writer:
            pcap_writer.close()


# --- 2. GUI Application (Main Process) ---

class PacketStats:
    """Holds aggregated statistics in the Main Process."""
    def __init__(self):
        self.reset()

    def reset(self):
        self.packet_count = 0
        self.byte_count = 0
        # Aggregates bytes per IP address
        self.ip_stats = defaultdict(lambda: {"bytes": 0, "packets": 0})

    def update(self, pkt_len, src_ip, dst_ip):
        self.packet_count += 1
        self.byte_count += pkt_len
        
        # Attribute usage to both source and dest IPs
        if src_ip:
            self.ip_stats[src_ip]["bytes"] += pkt_len
            self.ip_stats[src_ip]["packets"] += 1
        if dst_ip:
            self.ip_stats[dst_ip]["bytes"] += pkt_len
            self.ip_stats[dst_ip]["packets"] += 1

class NetworkAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Traffic Analyzer Pro (Top Talkers Edition)")
        self.resize(1400, 900)
        
        # --- Multiprocessing Setup ---
        self.data_queue = Queue()
        self.stop_event = Event()
        self.sniffer_process = None
        
        # --- Data State ---
        self.stats = PacketStats()
        self.pps_history = deque([0]*GRAPH_HISTORY_SIZE, maxlen=GRAPH_HISTORY_SIZE)
        self.kbps_history = deque([0]*GRAPH_HISTORY_SIZE, maxlen=GRAPH_HISTORY_SIZE)
        
        # Smoothing Variables
        self.current_pps_smooth = 0
        self.current_kbps_smooth = 0
        
        self.setup_styling()
        self.setup_ui()

        # Update Timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_dashboard)
        self.update_timer.start(UI_UPDATE_INTERVAL_MS)

    def setup_styling(self):
        QApplication.setStyle(QStyleFactory.create("Fusion"))
        
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(45, 45, 45))
        dark_palette.setColor(QPalette.WindowText, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Base, QColor(30, 30, 30))
        dark_palette.setColor(QPalette.AlternateBase, QColor(45, 45, 45))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.ToolTipText, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Text, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Button, QColor(45, 45, 45))
        dark_palette.setColor(QPalette.ButtonText, QColor(220, 220, 220))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
        QApplication.setPalette(dark_palette)
        
        self.setStyleSheet("""
            QWidget { color: #e0e0e0; font-family: "Segoe UI", sans-serif; }
            QGroupBox { border: 1px solid #555; margin-top: 0.8em; font-weight: bold; color: #DDD; border-radius: 4px; }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 5px; }
            QComboBox { background-color: #1e1e1e; color: #f0f0f0; border: 1px solid #555; padding: 5px; border-radius: 3px; min-height: 20px; }
            QComboBox:hover { border: 1px solid #2a82da; }
            QComboBox::drop-down { border: 0px; background: #1e1e1e; width: 25px; }
            QComboBox QAbstractItemView { background-color: #1e1e1e; color: #f0f0f0; selection-background-color: #2a82da; border: 1px solid #555; }
            QTableWidget { background-color: #1e1e1e; color: #f0f0f0; gridline-color: #444; border: 1px solid #444; }
            QHeaderView::section { background-color: #333; color: #f0f0f0; padding: 5px; border: 1px solid #444; }
            QTextEdit { background-color: #1e1e1e; color: #00FF7F; border: 1px solid #444; }
            QCheckBox { spacing: 8px; color: #ddd; }
            QCheckBox::indicator { width: 18px; height: 18px; }
        """)
        pg.setConfigOptions(antialias=True, background='#1e1e1e', foreground='#999')

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)

        # --- 1. Configuration Bar ---
        control_group = QGroupBox("Capture Settings")
        top_layout = QHBoxLayout(control_group)
        
        self.iface_combo = QComboBox()
        self.populate_interfaces()
        self.iface_combo.setMinimumWidth(350)
        
        self.filter_combo = QComboBox()
        self.filter_combo.setEditable(True)
        self.filter_combo.addItems(["", "tcp", "udp", "port 80", "port 443", "icmp"])
        self.filter_combo.lineEdit().setPlaceholderText("BPF Filter (e.g., 'tcp port 80')")
        self.filter_combo.setMinimumWidth(200)
        
        self.check_save_pcap = QCheckBox("Save to .pcap")
        self.check_save_pcap.setToolTip("Auto-save capture with timestamp filename")
        self.check_save_pcap.setChecked(False)
        
        self.btn_start = QPushButton("Start Capture")
        self.btn_start.setCursor(Qt.PointingHandCursor)
        self.btn_start.setStyleSheet("background-color: #1b5e20; color: white; border-radius: 4px; padding: 8px 16px; font-weight: bold;")
        self.btn_start.clicked.connect(self.start_capture)
        
        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setCursor(Qt.PointingHandCursor)
        self.btn_stop.setStyleSheet("background-color: #b71c1c; color: white; border-radius: 4px; padding: 8px 16px; font-weight: bold;")
        self.btn_stop.clicked.connect(self.stop_capture)
        self.btn_stop.setEnabled(False)

        top_layout.addWidget(QLabel("Interface:"))
        top_layout.addWidget(self.iface_combo)
        top_layout.addWidget(QLabel("Filter:"))
        top_layout.addWidget(self.filter_combo, 1)
        top_layout.addWidget(self.check_save_pcap)
        top_layout.addWidget(self.btn_start)
        top_layout.addWidget(self.btn_stop)
        main_layout.addWidget(control_group)

        # --- 2. Dashboard Cards ---
        metrics_layout = QHBoxLayout()
        self.card_pkts = self.create_metric_card("Total Packets", "0")
        self.card_bytes = self.create_metric_card("Total Data (MB)", "0.00")
        self.card_pps = self.create_metric_card("Packets / Sec", "0")
        self.card_kbps = self.create_metric_card("Throughput (KB/s)", "0.00")
        
        metrics_layout.addWidget(self.card_pkts)
        metrics_layout.addWidget(self.card_bytes)
        metrics_layout.addWidget(self.card_pps)
        metrics_layout.addWidget(self.card_kbps)
        main_layout.addLayout(metrics_layout)

        # --- 3. Splitter (Graphs | Top Talkers | Logs) ---
        splitter = QSplitter(Qt.Vertical)
        
        # Graph Container
        graph_container = QWidget()
        graph_cont_layout = QVBoxLayout(graph_container)
        graph_cont_layout.setContentsMargins(0, 0, 0, 0)
        
        # Toolbar
        graph_toolbar = QHBoxLayout()
        graph_toolbar.addStretch()
        
        self.check_smooth = QCheckBox("Smooth Graph")
        self.check_smooth.setChecked(True)
        self.check_smooth.setStyleSheet("color: #ccc; font-weight: bold; margin-right: 15px;")
        
        self.btn_reset_graph = QPushButton("Reset / Auto-Fit")
        self.btn_reset_graph.setCursor(Qt.PointingHandCursor)
        self.btn_reset_graph.setStyleSheet("background-color: #444; color: white; border: 1px solid #666; padding: 4px 10px; border-radius: 3px;")
        self.btn_reset_graph.clicked.connect(self.reset_graph_view)
        
        graph_toolbar.addWidget(self.check_smooth)
        graph_toolbar.addWidget(self.btn_reset_graph)
        
        # Graphs
        graph_layout = QHBoxLayout()
        self.plot_pps = pg.PlotWidget(title="Packet Rate (PPS)")
        self.plot_pps.showGrid(x=True, y=True, alpha=0.3)
        self.plot_pps.setLabel('left', 'Packets')
        self.curve_pps = self.plot_pps.plot(pen=pg.mkPen(color='#4fc3f7', width=2))
        
        self.plot_kbps = pg.PlotWidget(title="Throughput (KB/s)")
        self.plot_kbps.showGrid(x=True, y=True, alpha=0.3)
        self.plot_kbps.setLabel('left', 'Kilobytes')
        self.curve_kbps = self.plot_kbps.plot(pen=pg.mkPen(color='#ffab91', width=2))

        graph_layout.addWidget(self.plot_pps)
        graph_layout.addWidget(self.plot_kbps)
        
        graph_cont_layout.addLayout(graph_toolbar)
        graph_cont_layout.addLayout(graph_layout)
        splitter.addWidget(graph_container)

        #  Top Talkers Table
        flow_group = QGroupBox("Top Talkers (Highest Bandwidth IPs)")
        flow_layout = QVBoxLayout(flow_group)
        self.table_talkers = QTableWidget(0, 3)
        self.table_talkers.setHorizontalHeaderLabels(["IP Address", "Total Data Transferred", "Packets Involved"])
        self.table_talkers.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_talkers.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table_talkers.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table_talkers.setAlternatingRowColors(True)
        self.table_talkers.verticalHeader().setVisible(False)
        self.table_talkers.setSelectionBehavior(QTableWidget.SelectRows)
        flow_layout.addWidget(self.table_talkers)
        splitter.addWidget(flow_group)

        # Log
        log_group = QGroupBox("Live Packet Log")
        log_layout = QVBoxLayout(log_group)
        self.text_log = QTextEdit()
        self.text_log.setReadOnly(True)
        self.text_log.setFont(QFont("Consolas", 9)) 
        log_layout.addWidget(self.text_log)
        splitter.addWidget(log_group)

        splitter.setSizes([300, 200, 150]) # Adjusted sizes
        main_layout.addWidget(splitter)

    def create_metric_card(self, title, value):
        frame = QFrame()
        frame.setStyleSheet("background-color: #333; border-radius: 6px; border: 1px solid #444;")
        layout = QVBoxLayout(frame)
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #aaa; font-size: 11px; text-transform: uppercase; font-weight: bold;")
        lbl_val = QLabel(value)
        lbl_val.setStyleSheet("color: #fff; font-size: 22px; font-weight: bold;")
        lbl_val.setAlignment(Qt.AlignRight)
        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)
        frame.val_label = lbl_val
        return frame

    def populate_interfaces(self):
        try:
            ifaces = get_windows_if_list()
            for i in ifaces:
                ips = i.get("ips", [])
                if ips:
                    self.iface_combo.addItem(f"{i['name']} ({', '.join(ips)})", i["name"])
        except:
            self.iface_combo.addItem("Error listing interfaces", None)

    def start_capture(self):
        iface = self.iface_combo.currentData()
        if not iface:
            return

        flt = self.filter_combo.currentText().strip()
        
        # Reset GUI Data
        self.stats.reset()
        self.pps_history = deque([0]*GRAPH_HISTORY_SIZE, maxlen=GRAPH_HISTORY_SIZE)
        self.kbps_history = deque([0]*GRAPH_HISTORY_SIZE, maxlen=GRAPH_HISTORY_SIZE)
        self.text_log.clear()
        self.table_talkers.setRowCount(0)
        
        # Drain any old data in queue
        while not self.data_queue.empty():
            self.data_queue.get()

        # Generate PCAP Filename (if enabled)
        pcap_file = None
        if self.check_save_pcap.isChecked():
            ts_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            pcap_file = f"capture_{ts_str}.pcap"
            self.log_message(f"[Disk] Recording to: {pcap_file}")

        # START MULTIPROCESSING
        self.stop_event.clear()
        self.sniffer_process = Process(
            target=run_sniffer_process,
            args=(iface, flt, self.data_queue, self.stop_event, pcap_file)
        )
        self.sniffer_process.start()
        
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.filter_combo.setEnabled(False)
        self.check_save_pcap.setEnabled(False)
        
        self.log_message(f"--- Capture Started (PID: {self.sniffer_process.pid}) ---")
        self.reset_graph_view()

    def stop_capture(self):
        if self.sniffer_process and self.sniffer_process.is_alive():
            self.stop_event.set()
            self.sniffer_process.join(timeout=2)
            if self.sniffer_process.is_alive():
                self.sniffer_process.terminate()
        
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.iface_combo.setEnabled(True)
        self.filter_combo.setEnabled(True)
        self.check_save_pcap.setEnabled(True)
        self.log_message("--- Capture Stopped ---")

    def reset_graph_view(self):
        self.plot_pps.enableAutoRange(axis='xy')
        self.plot_kbps.enableAutoRange(axis='xy')

    def log_message(self, msg):
        self.text_log.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    def update_dashboard(self):
        items_processed = 0
        new_packet_count = 0
        new_byte_count = 0
        logs_to_add = []

        while not self.data_queue.empty() and items_processed < 1000:
            try:
                data = self.data_queue.get_nowait()
                if data[0] == "ERROR":
                    self.log_message(f"Error: {data[1]}")
                    continue
                
                # Unpack Tuple
                ts, pkt_len, proto, src_ip, dst_ip, summary = data
                
                # Update Stats
                self.stats.update(pkt_len, src_ip, dst_ip)
                
                new_packet_count += 1
                new_byte_count += pkt_len
                
                if len(logs_to_add) < 20: 
                    t_str = time.strftime("%H:%M:%S", time.localtime(ts))
                    logs_to_add.append(f"[{t_str}] {summary}")
                
                items_processed += 1
            except py_queue.Empty:
                break

        if logs_to_add:
            self.text_log.append("\n".join(logs_to_add))

        # Rate Calculations
        raw_pps = new_packet_count * (1000 / UI_UPDATE_INTERVAL_MS)
        raw_bps = new_byte_count * (1000 / UI_UPDATE_INTERVAL_MS)
        raw_kbps = raw_bps / 1024.0

        # Smoothing
        if self.check_smooth.isChecked():
            alpha = 0.1
            self.current_pps_smooth = (raw_pps * alpha) + (self.current_pps_smooth * (1 - alpha))
            self.current_kbps_smooth = (raw_kbps * alpha) + (self.current_kbps_smooth * (1 - alpha))
            
            if self.current_pps_smooth < 0.01: self.current_pps_smooth = 0.0
            if self.current_kbps_smooth < 0.01: self.current_kbps_smooth = 0.0

            plot_pps = self.current_pps_smooth
            plot_kbps = self.current_kbps_smooth
        else:
            plot_pps = raw_pps
            plot_kbps = raw_kbps
            self.current_pps_smooth = raw_pps
            self.current_kbps_smooth = raw_kbps

        # Update Graphs
        if not self.btn_stop.isEnabled() and plot_pps == 0 and plot_kbps == 0:
            pass 
        else:
            self.pps_history.append(plot_pps)
            self.kbps_history.append(plot_kbps)
            self.curve_pps.setData(list(self.pps_history))
            self.curve_kbps.setData(list(self.kbps_history))

        # Update Cards
        total_mb = self.stats.byte_count / (1024 * 1024)
        self.card_pkts.val_label.setText(str(self.stats.packet_count))
        self.card_bytes.val_label.setText(f"{total_mb:.2f}")
        self.card_pps.val_label.setText(f"{int(plot_pps)}")
        self.card_kbps.val_label.setText(f"{plot_kbps:.2f}")

        # --- UPDATE TOP TALKERS TABLE (Top 3 IPs) ---
        # Sort IP stats by Bytes, descending
        top_talkers = sorted(
            self.stats.ip_stats.items(),
            key=lambda item: item[1]['bytes'],
            reverse=True
        )[:3]  # Only top 3
        
        self.table_talkers.setRowCount(len(top_talkers))
        for row, (ip, data) in enumerate(top_talkers):
            
            # Helper to make items read-only
            def item(txt):
                it = QTableWidgetItem(str(txt))
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                return it

            # Formatting bytes to human readable
            b = data['bytes']
            if b > 1024 * 1024:
                size_str = f"{b / (1024*1024):.2f} MB"
            elif b > 1024:
                size_str = f"{b / 1024:.2f} KB"
            else:
                size_str = f"{b} B"

            self.table_talkers.setItem(row, 0, item(ip))
            self.table_talkers.setItem(row, 1, item(size_str))
            self.table_talkers.setItem(row, 2, item(data['packets']))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    font = QFont("Segoe UI", 10)
    app.setFont(font)

    window = NetworkAnalyzer()
    window.show()
    sys.exit(app.exec())

