from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox
from scapy.all import IP, ICMP, sr1
from scapy.error import Scapy_Exception
import socket
import threading

class TracerouteWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.tracing = False

    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input for destination IP
        input_layout = QHBoxLayout()
        self.destination_input = QLineEdit()
        self.destination_input.setPlaceholderText("Enter IP address for traceroute")
        self.start_button = QPushButton("Start Traceroute")
        self.stop_button = QPushButton("Stop Traceroute")
        self.stop_button.setEnabled(False)
        
        input_layout.addWidget(QLabel("Destination:"))
        input_layout.addWidget(self.destination_input)
        input_layout.addWidget(self.start_button)
        input_layout.addWidget(self.stop_button)
        
        layout.addLayout(input_layout)
        
        # Output display
        self.output_display = QTextEdit()
        self.output_display.setReadOnly(True)
        layout.addWidget(self.output_display)
        
        self.setLayout(layout)
        
        # Connect buttons
        self.start_button.clicked.connect(self.start_traceroute)
        self.stop_button.clicked.connect(self.stop_traceroute)
    
    def start_traceroute(self):
        if self.tracing:
            QMessageBox.warning(self, "Warning", "Traceroute is already in progress.")
            return
        
        destination = self.destination_input.text().strip()
        if not destination:
            QMessageBox.warning(self, "Input Error", "Please enter a destination IP address.")
            return
        
        self.tracing = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.output_display.clear()
        
        # Start traceroute in a separate thread
        self.traceroute_thread = threading.Thread(target=self.perform_traceroute, args=(destination,))
        self.traceroute_thread.start()
    
    def stop_traceroute(self):
        self.tracing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.output_display.append("Traceroute stopped by user.")
    
    def perform_traceroute(self, destination):
        self.output_display.append(f"Traceroute to {destination}, 30 hops max:")
        for ttl in range(1, 31):
            if not self.tracing:
                break
            packet = IP(dst=destination, ttl=ttl) / ICMP()
            try:
                response = sr1(packet, verbose=0, timeout=3)
            except Scapy_Exception as e:
                self.output_display.append(f"Error sending packet: {e}")
                continue
            
            if response is None:
                self.output_display.append(f"Hop {ttl}: *")
            else:
                try:
                    hostname = socket.gethostbyaddr(response.src)[0]
                except socket.herror:
                    hostname = response.src
                
                if response.type == 0:  # Echo Reply
                    self.output_display.append(f"Hop {ttl}: {hostname} ({response.src})")
                    self.output_display.append("The final host reached")
                    break
                elif response.type == 11:  # Time Exceeded
                    self.output_display.append(f"Hop {ttl}: {hostname} ({response.src}) (ICMP time exceeded)")
                else:
                    self.output_display.append(f"Hop {ttl}: {hostname} ({response.src}) (ICMP type {response.type})")
        else:
            self.output_display.append("Reached max TTL without reaching the final host.")
        
        # Reset buttons after traceroute
        self.tracing = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
