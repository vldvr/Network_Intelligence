from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox
from scapy.all import sniff, get_if_list, IP, TCP, UDP, Ether
from datetime import datetime
import threading

class PacketSnifferWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.sniffing = False

    def init_ui(self):
        layout = QVBoxLayout()

        # Filters
        filters_layout = QHBoxLayout()
        
        self.protocol_input = QLineEdit()
        self.protocol_input.setPlaceholderText("Protocol (tcp/udp)")
        
        self.src_port_input = QLineEdit()
        self.src_port_input.setPlaceholderText("Source Port")
        
        self.dst_port_input = QLineEdit()
        self.dst_port_input.setPlaceholderText("Destination Port")
        
        self.src_ip_input = QLineEdit()
        self.src_ip_input.setPlaceholderText("Source IP")
        
        self.dst_ip_input = QLineEdit()
        self.dst_ip_input.setPlaceholderText("Destination IP")
        
        self.src_mac_input = QLineEdit()
        self.src_mac_input.setPlaceholderText("Source MAC")
        
        self.dst_mac_input = QLineEdit()
        self.dst_mac_input.setPlaceholderText("Destination MAC")
        
        filters_layout.addWidget(QLabel("Protocol:"))
        filters_layout.addWidget(self.protocol_input)
        filters_layout.addWidget(QLabel("Src Port:"))
        filters_layout.addWidget(self.src_port_input)
        filters_layout.addWidget(QLabel("Dst Port:"))
        filters_layout.addWidget(self.dst_port_input)
        filters_layout.addWidget(QLabel("Src IP:"))
        filters_layout.addWidget(self.src_ip_input)
        filters_layout.addWidget(QLabel("Dst IP:"))
        filters_layout.addWidget(self.dst_ip_input)
        filters_layout.addWidget(QLabel("Src MAC:"))
        filters_layout.addWidget(self.src_mac_input)
        filters_layout.addWidget(QLabel("Dst MAC:"))
        filters_layout.addWidget(self.dst_mac_input)
        
        layout.addLayout(filters_layout)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Sniffing")
        self.stop_button = QPushButton("Stop Sniffing")
        self.stop_button.setEnabled(False)
        
        buttons_layout.addWidget(self.start_button)
        buttons_layout.addWidget(self.stop_button)
        
        layout.addLayout(buttons_layout)
        
        # Log Display
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        layout.addWidget(self.log_display)
        
        self.setLayout(layout)
        
        # Connect buttons
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button.clicked.connect(self.stop_sniffing)
    
    def start_sniffing(self):
        if self.sniffing:
            QMessageBox.warning(self, "Warning", "Sniffing is already in progress.")
            return
        
        # Get network interfaces
        interfaces = get_if_list()
        if not interfaces:
            QMessageBox.critical(self, "Error", "No network interfaces found.")
            return
        
        # Let user choose interface
        iface, ok = self.get_interface_choice(interfaces)
        if not ok:
            return
        
        # Prepare filters
        self.filters = {
            'protocol': self.protocol_input.text().lower(),
            'source_port': self.src_port_input.text(),
            'destination_port': self.dst_port_input.text(),
            'source_ip': self.src_ip_input.text(),
            'destination_ip': self.dst_ip_input.text(),
            'source_mac': self.src_mac_input.text(),
            'destination_mac': self.dst_mac_input.text(),
        }
        
        # Start sniffing in a separate thread
        self.sniffing = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.sniff_thread = threading.Thread(target=self.sniff_packets, args=(iface,))
        self.sniff_thread.start()
    
    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
    
    def sniff_packets(self, iface):
        def log_packet(packet):
            if not self.sniffing:
                return False  # Stop sniffing
            
            # Determine protocol
            protocol = None
            if IP in packet:
                if TCP in packet:
                    protocol = 'tcp'
                elif UDP in packet:
                    protocol = 'udp'
                else:
                    protocol = 'ip'
            else:
                return
            
            # Apply protocol filter
            if self.filters['protocol'] and self.filters['protocol'] != protocol:
                return
            
            # Extract packet details
            source_ip = packet[IP].src if IP in packet else ''
            destination_ip = packet[IP].dst if IP in packet else ''
            source_mac = packet[Ether].src if Ether in packet else ''
            destination_mac = packet[Ether].dst if Ether in packet else ''
            source_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else '')
            destination_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else '')
            
            # Apply other filters
            if (self.filters['source_ip'] and self.filters['source_ip'] != source_ip) or \
               (self.filters['destination_ip'] and self.filters['destination_ip'] != destination_ip) or \
               (self.filters['source_mac'] and self.filters['source_mac'] != source_mac) or \
               (self.filters['destination_mac'] and self.filters['destination_mac'] != destination_mac) or \
               (self.filters['source_port'] and self.filters['source_port'] != str(source_port)) or \
               (self.filters['destination_port'] and self.filters['destination_port'] != str(destination_port)):
                return
            
            # Log the packet
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_entry = f"{timestamp} - {source_mac} -> {destination_mac} ({protocol.upper()}) {source_ip}:{source_port} -> {destination_ip}:{destination_port}"
            self.log_display.append(log_entry)
        
        try:
            sniff(prn=log_packet, store=False, iface=iface, stop_filter=lambda x: not self.sniffing)
        except Exception as e:
            self.log_display.append(f"Error: {e}")
        
        # Reset buttons after sniffing stops
        self.sniffing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
    
    def get_interface_choice(self, interfaces):
        from PyQt5.QtWidgets import QInputDialog
        iface, ok = QInputDialog.getItem(self, "Select Interface", "Choose a network interface:", interfaces, 0, False)
        return iface, ok
