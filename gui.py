from PyQt5.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout
from packet_sniffer import PacketSnifferWidget
from traceroute import TracerouteWidget
from geolocation import GeolocationWidget
from network_scanner import NetworkScannerWidget

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Utility")
        self.setGeometry(100, 100, 800, 600)
        
        # Initialize tabs
        self.tabs = QTabWidget()
        
        # Add individual widgets to tabs
        self.tabs.addTab(PacketSnifferWidget(), "Packet Sniffer")
        self.tabs.addTab(TracerouteWidget(), "Traceroute")
        self.tabs.addTab(GeolocationWidget(), "Geolocation")
        self.tabs.addTab(NetworkScannerWidget(), "Network Scanner")
        
        self.setCentralWidget(self.tabs)
