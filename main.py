import sys
import time
import os
import socket
import requests
from datetime import datetime
from multiprocessing import Process, Queue, Event
import queue as py_queue
from concurrent.futures import ThreadPoolExecutor

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QStyleFactory, QCheckBox, QSplitter, QTextEdit, QFileDialog
)
from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QFont, QColor

from scapy.arch.windows import get_windows_if_list
from scapy.all import conf

# Import sniffer
from sniffer import run_sniffer_process

UI_UPDATE_INTERVAL_MS = 100 

def get_plain_english_summary(proto, sport, dport):
    ports = {sport, dport}
    if 443 in ports: return "Encrypted Web Traffic (HTTPS)"
    if 80 in ports: return "Unencrypted Web Traffic (HTTP)"
    if 53 in ports: return "Domain Name Request (DNS)"
    if 21 in ports: return "File Transfer (FTP)"
    if 22 in ports: return "Secure Shell (SSH)"
    if 23 in ports: return "Insecure Shell (Telnet)"
    if 445 in ports: return "Windows File Sharing (SMB)"
    if 3389 in ports: return "Remote Desktop (RDP)"
    if proto == "ICMP": return "Ping / Network Check"
    if proto == "ARP": return "Local Network MAC Resolution"
    return f"{proto} Traffic"

class NetworkAnalyzer(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Sentinel Network Monitor")
        self.resize(1600, 1000)
        
        self.data_queue = Queue()
        self.stop_event = Event()
        self.sniffer_process = None
        
        self.total_packets = 0
        self.total_bytes = 0
        self.packet_log_list = []
        
        # Async resolution
        self.ip_cache = {}
        self.executor = ThreadPoolExecutor(max_workers=5)
        self.local_ips = set()
        
        self.setup_styling()
        self.setup_ui()
        
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_dashboard)
        self.update_timer.start(UI_UPDATE_INTERVAL_MS)

    def resolve_ip_async(self, ip):
        """Resolves hostname and country in the background"""
        if ip in self.ip_cache or ip == "Unknown" or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") or ip == "127.0.0.1":
            if ip not in self.ip_cache:
                self.ip_cache[ip] = {"host": ip, "geo": "Local"}
            return
            
        # Placeholder so we don't queue it twice
        self.ip_cache[ip] = {"host": ip, "geo": ""}
        
        def fetch():
            host = ip
            geo = ""
            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass
                
            try:
                r = requests.get(f"http://ip-api.com/json/{ip}?fields=country", timeout=2)
                if r.status_code == 200:
                    geo = r.json().get("country", "")
            except Exception:
                pass
                
            self.ip_cache[ip] = {"host": host, "geo": geo}
            
        self.executor.submit(fetch)

    def setup_styling(self):
        QApplication.setStyle(QStyleFactory.create("Fusion"))
        self.setStyleSheet("""
            QMainWindow {
                background-color: #0A0A0A;
            }
            QWidget {
                color: #D4D4D4;
                font-family: "Consolas", "Courier New", monospace;
            }
            QComboBox {
                background-color: #1E1E1E;
                color: #D4D4D4;
                border: 1px solid #333333;
                padding: 6px 12px;
                border-radius: 4px;
                min-height: 24px;
            }
            QComboBox::drop-down { border: 0px; }
            QTableWidget {
                background-color: #0A0A0A;
                color: #CCCCCC;
                gridline-color: #1A1A1A;
                border: 1px solid #333333;
                border-radius: 4px;
                font-size: 13px;
            }
            QHeaderView::section {
                background-color: #1E1E1E;
                color: #888888;
                padding: 8px;
                border: 1px solid #0A0A0A;
                font-weight: bold;
                text-transform: uppercase;
                font-size: 11px;
            }
            QTableWidget::item:selected {
                background-color: #264F78;
                color: #FFFFFF;
            }
            QPushButton {
                background-color: #1E1E1E;
                color: #D4D4D4;
                border: 1px solid #333333;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #2D2D2D;
                border-color: #555555;
            }
            QPushButton:disabled {
                background-color: #111111;
                color: #555555;
                border-color: #222222;
            }
            QCheckBox {
                color: #D4D4D4;
                font-weight: bold;
                spacing: 8px;
            }
            QSplitter::handle {
                background-color: #333333;
            }
        """)

    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        # Control Bar
        control_layout = QHBoxLayout()
        
        self.iface_combo = QComboBox()
        self.populate_interfaces()
        self.iface_combo.setMinimumWidth(300)
        
        self.filter_combo = QComboBox()
        self.filter_combo.setEditable(True)
        self.filter_combo.addItems(["", "tcp", "udp", "port 80", "port 443", "icmp", "arp"])
        self.filter_combo.lineEdit().setPlaceholderText("BPF Filter (e.g., 'tcp port 80')")
        self.filter_combo.setMinimumWidth(200)
        
        self.check_pcap = QCheckBox("SAVE PCAP")
        
        self.btn_open_pcap = QPushButton("OPEN PCAP")
        self.btn_open_pcap.setCursor(Qt.PointingHandCursor)
        self.btn_open_pcap.clicked.connect(self.open_pcap)

        self.btn_start = QPushButton("START CAPTURE")
        self.btn_start.setCursor(Qt.PointingHandCursor)
        self.btn_start.clicked.connect(self.start_capture)
        
        self.btn_stop = QPushButton("STOP")
        self.btn_stop.setCursor(Qt.PointingHandCursor)
        self.btn_stop.clicked.connect(self.stop_capture)
        self.btn_stop.setEnabled(False)

        control_layout.addWidget(QLabel("INTERFACE:"))
        control_layout.addWidget(self.iface_combo)
        control_layout.addWidget(QLabel("FILTER:"))
        control_layout.addWidget(self.filter_combo, 1)
        control_layout.addWidget(self.check_pcap)
        control_layout.addWidget(self.btn_open_pcap)
        control_layout.addWidget(self.btn_start)
        control_layout.addWidget(self.btn_stop)
        
        main_layout.addLayout(control_layout)

        # Metrics Bar
        metrics_layout = QHBoxLayout()
        self.card_pkts = self.create_metric_card("TOTAL PACKETS", "0")
        self.card_bytes = self.create_metric_card("TOTAL VOLUME", "0.00 MB")
        self.card_pps = self.create_metric_card("PACKET RATE", "0 pps")
        self.card_kbps = self.create_metric_card("THROUGHPUT", "0.00 KB/s")
        
        metrics_layout.addWidget(self.card_pkts)
        metrics_layout.addWidget(self.card_bytes)
        metrics_layout.addWidget(self.card_pps)
        metrics_layout.addWidget(self.card_kbps)
        main_layout.addLayout(metrics_layout)

        # Main Splitter
        self.main_splitter = QSplitter(Qt.Vertical)

        # Terminal Stream (Top Half)
        self.table_packet_log = QTableWidget(0, 6)
        self.table_packet_log.setHorizontalHeaderLabels(["TIME", "PROTOCOL", "SOURCE", "DESTINATION", "SIZE", "SUMMARY"])
        self.table_packet_log.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table_packet_log.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_packet_log.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table_packet_log.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table_packet_log.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table_packet_log.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.table_packet_log.verticalHeader().setVisible(False)
        self.table_packet_log.setSelectionBehavior(QTableWidget.SelectRows)
        self.table_packet_log.setShowGrid(False)
        self.table_packet_log.itemSelectionChanged.connect(self.on_packet_selected)

        self.main_splitter.addWidget(self.table_packet_log)

        # Inspection Panels (Bottom Half)
        self.inspection_widget = QWidget()
        insp_layout = QHBoxLayout(self.inspection_widget)
        insp_layout.setContentsMargins(0, 10, 0, 0)
        insp_layout.setSpacing(20)
        
        # Headers Pane
        headers_frame = QFrame()
        headers_layout = QVBoxLayout(headers_frame)
        headers_layout.setContentsMargins(0, 0, 0, 0)
        lbl_hdrs = QLabel("DEEP OSI HEADERS (L2 - L4)")
        lbl_hdrs.setStyleSheet("color: #888888; font-size: 11px; font-weight: bold;")
        self.text_headers = QTextEdit()
        self.text_headers.setReadOnly(True)
        self.text_headers.setStyleSheet("background-color: #050505; color: #569CD6; border: 1px solid #333333; font-family: 'Consolas'; font-size: 12px; padding: 10px;")
        headers_layout.addWidget(lbl_hdrs)
        headers_layout.addWidget(self.text_headers)
        
        # Hex Dump Pane
        hex_frame = QFrame()
        hex_layout = QVBoxLayout(hex_frame)
        hex_layout.setContentsMargins(0, 0, 0, 0)
        lbl_hex = QLabel("RAW HEX DUMP (PAYLOAD)")
        lbl_hex.setStyleSheet("color: #888888; font-size: 11px; font-weight: bold;")
        self.text_hex = QTextEdit()
        self.text_hex.setReadOnly(True)
        self.text_hex.setStyleSheet("background-color: #050505; color: #4EC9B0; border: 1px solid #333333; font-family: 'Consolas'; font-size: 12px; padding: 10px;")
        hex_layout.addWidget(lbl_hex)
        hex_layout.addWidget(self.text_hex)
        
        insp_layout.addWidget(headers_frame)
        insp_layout.addWidget(hex_frame)
        
        self.main_splitter.addWidget(self.inspection_widget)
        self.main_splitter.setSizes([700, 300]) # 70% top, 30% bottom
        
        main_layout.addWidget(self.main_splitter)

    def create_metric_card(self, title, value):
        frame = QFrame()
        frame.setStyleSheet("""
            QFrame {
                background-color: #141414; 
                border-radius: 4px; 
                border: 1px solid #222222;
            }
        """)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(15, 10, 15, 10)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #888888; font-size: 11px; font-weight: bold; border:0px; background-color: transparent;")
        
        lbl_val = QLabel(value)
        lbl_val.setStyleSheet("color: #FFFFFF; font-size: 20px; font-weight: bold; border:0px; background-color: transparent;")
        
        layout.addWidget(lbl_title)
        layout.addWidget(lbl_val)
        frame.val_label = lbl_val
        return frame

    def populate_interfaces(self):
        default_index = 0
        self.iface_ips = {} # Map interface name -> List of IPs
        try:
            default_iface = conf.iface.name if hasattr(conf.iface, "name") else None
            ifaces = get_windows_if_list()
            idx = 0
            for i in ifaces:
                ips = i.get("ips", [])
                if ips:
                    self.iface_combo.addItem(f"{i['name']} ({', '.join(ips)})", i["name"])
                    self.iface_ips[i["name"]] = ips
                    if default_iface and i["name"] == default_iface:
                        default_index = idx
                    idx += 1
        except Exception:
            self.iface_combo.addItem("Error listing interfaces", None)
            
        self.iface_combo.setCurrentIndex(default_index)

    def open_pcap(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open PCAP File", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)")
        if not file_path:
            return
            
        self.total_packets = 0
        self.total_bytes = 0
        self.packet_log_list.clear()
        
        self.table_packet_log.setRowCount(0)
        self.text_headers.clear()
        self.text_hex.clear()
        
        while not self.data_queue.empty():
            try:
                self.data_queue.get_nowait()
            except py_queue.Empty:
                break

        self.stop_event.clear()
        self.sniffer_process = Process(
            target=run_sniffer_process,
            args=(None, "", self.data_queue, self.stop_event, None, file_path) 
        )
        self.sniffer_process.start()
        
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_open_pcap.setEnabled(False)
        self.iface_combo.setEnabled(False)
        self.filter_combo.setEnabled(False)
        self.check_pcap.setEnabled(False)

    def start_capture(self):
        iface = self.iface_combo.currentData()
        if not iface:
            return

        # Get local IP for inbound/outbound arrows
        ips = self.iface_ips.get(iface, [])
        self.local_ips = set(ips)

        flt = self.filter_combo.currentText().strip()
        
        pcap_file = None
        if self.check_pcap.isChecked():
            ts_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            pcap_file = f"capture_{ts_str}.pcap"
        
        self.total_packets = 0
        self.total_bytes = 0
        self.packet_log_list.clear()
        
        self.table_packet_log.setRowCount(0)
        self.text_headers.clear()
        self.text_hex.clear()
        
        while not self.data_queue.empty():
            try:
                self.data_queue.get_nowait()
            except py_queue.Empty:
                break

        self.stop_event.clear()
        self.sniffer_process = Process(
            target=run_sniffer_process,
            args=(iface, flt, self.data_queue, self.stop_event, pcap_file, None) 
        )
        self.sniffer_process.start()
        
        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.btn_open_pcap.setEnabled(False)
        self.iface_combo.setEnabled(False)
        self.filter_combo.setEnabled(False)
        self.check_pcap.setEnabled(False)

    def stop_capture(self):
        if self.sniffer_process and self.sniffer_process.is_alive():
            self.stop_event.set()
            self.sniffer_process.join(timeout=2.0)
            if self.sniffer_process.is_alive():
                self.sniffer_process.terminate()
        
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.btn_open_pcap.setEnabled(True)
        self.iface_combo.setEnabled(True)
        self.filter_combo.setEnabled(True)
        self.check_pcap.setEnabled(True)

    def update_dashboard(self):
        items_processed = 0
        new_packet_count = 0
        new_byte_count = 0
        
        while not self.data_queue.empty() and items_processed < 200:
            try:
                data = self.data_queue.get_nowait()
                if data[0] == "ERROR":
                    continue
                
                ts, pkt_len, proto, src_ip, sport, dst_ip, dport, summary, details_str, hexdump_str = data
                
                self.total_packets += 1
                self.total_bytes += pkt_len
                new_packet_count += 1
                new_byte_count += pkt_len

                # Direction Arrow
                direction = "  "
                if src_ip in self.local_ips:
                    direction = "⬆ [OUT]"
                elif dst_ip in self.local_ips:
                    direction = "⬇ [IN] "

                # Trigger Async Resolution for external IPs
                self.resolve_ip_async(src_ip)
                self.resolve_ip_async(dst_ip)
                
                # Fetch from cache if ready
                s_info = self.ip_cache.get(src_ip, {"host": src_ip, "geo": ""})
                d_info = self.ip_cache.get(dst_ip, {"host": dst_ip, "geo": ""})
                
                s_display = s_info["host"]
                if s_info["geo"] and s_info["geo"] != "Local":
                    s_display += f" ({s_info['geo']})"
                if sport: s_display += f":{sport}"
                    
                d_display = d_info["host"]
                if d_info["geo"] and d_info["geo"] != "Local":
                    d_display += f" ({d_info['geo']})"
                if dport: d_display += f":{dport}"

                # Human Readable Summary with TCP Flags appended if applicable
                human_summary = get_plain_english_summary(proto, sport, dport)

                pkt_obj = {
                    "time": time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int((ts % 1) * 1000):03d}",
                    "proto": proto,
                    "src": f"{direction} {s_display}",
                    "dst": d_display,
                    "len": str(pkt_len),
                    "summary": human_summary,
                    "direction": direction.strip(),
                    "details": details_str,
                    "hexdump": hexdump_str
                }
                
                self.packet_log_list.append(pkt_obj)
                if len(self.packet_log_list) > 1000:
                    self.packet_log_list.pop(0)
                    
                items_processed += 1
            except py_queue.Empty:
                break

        if items_processed > 0:
            self.refresh_packet_log_table()

        raw_pps = new_packet_count * (1000 / UI_UPDATE_INTERVAL_MS)
        raw_kbps = (new_byte_count / 1024.0) * (1000 / UI_UPDATE_INTERVAL_MS)

        self.card_pkts.val_label.setText(f"{self.total_packets:,}")
        self.card_bytes.val_label.setText(f"{self.total_bytes / (1024*1024):.2f} MB")
        self.card_pps.val_label.setText(f"{int(raw_pps)} pps")
        self.card_kbps.val_label.setText(f"{raw_kbps:.2f} KB/s")

    def refresh_packet_log_table(self):
        colors = {
            "TCP": QColor("#569CD6"),
            "HTTP": QColor("#569CD6"),
            "HTTPS": QColor("#569CD6"),
            "UDP": QColor("#CE9178"),
            "DNS": QColor("#C586C0"),
            "ICMP": QColor("#F44747"),
            "ARP": QColor("#4EC9B0"),
            "Other": QColor("#9CDCFE")
        }

        self.table_packet_log.blockSignals(True)
        self.table_packet_log.setUpdatesEnabled(False)
        self.table_packet_log.setRowCount(0)
        
        for pkt in self.packet_log_list:
            row = self.table_packet_log.rowCount()
            self.table_packet_log.insertRow(row)

            def item(txt):
                it = QTableWidgetItem(str(txt))
                it.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                c = colors.get(pkt["proto"], colors["Other"])
                
                if "[OUT]" in txt:
                    it.setForeground(QColor("#D7BA7D"))
                elif "[IN]" in txt:
                    it.setForeground(QColor("#9CDCFE"))
                else:
                    it.setForeground(c)
                return it

            self.table_packet_log.setItem(row, 0, item(pkt["time"]))
            self.table_packet_log.setItem(row, 1, item(pkt["proto"]))
            self.table_packet_log.setItem(row, 2, item(pkt["src"]))
            self.table_packet_log.setItem(row, 3, item(pkt["dst"]))
            self.table_packet_log.setItem(row, 4, item(pkt["len"]))
            self.table_packet_log.setItem(row, 5, item(pkt["summary"]))
                
        self.table_packet_log.setUpdatesEnabled(True)
        self.table_packet_log.blockSignals(False)
        
        # Only auto-scroll if the user hasn't selected a packet to inspect
        if not self.table_packet_log.selectedItems():
            self.table_packet_log.scrollToBottom()

    def on_packet_selected(self):
        selected_items = self.table_packet_log.selectedItems()
        if not selected_items:
            return
            
        row = selected_items[0].row()
        if row < len(self.packet_log_list):
            pkt = self.packet_log_list[row]
            self.text_headers.setText(pkt.get("details", "No header data available."))
            self.text_hex.setText(pkt.get("hexdump", "No hex dump available."))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NetworkAnalyzer()
    window.show()
    sys.exit(app.exec())