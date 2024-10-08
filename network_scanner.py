from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox, QRadioButton, QButtonGroup
import nmap
from geopy.distance import geodesic
import ipaddress
import requests
import threading
import time

class NetworkScannerWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.scanning = False

    def init_ui(self):
        layout = QVBoxLayout()
        
        # Radio buttons for private/public scan
        scan_type_layout = QHBoxLayout()
        self.private_radio = QRadioButton("Scan Private Network")
        self.public_radio = QRadioButton("Scan Public Network")
        self.private_radio.setChecked(True)
        self.scan_type_group = QButtonGroup()
        self.scan_type_group.addButton(self.private_radio)
        self.scan_type_group.addButton(self.public_radio)
        scan_type_layout.addWidget(self.private_radio)
        scan_type_layout.addWidget(self.public_radio)
        
        layout.addLayout(scan_type_layout)
        
        # Input fields
        network_layout = QHBoxLayout()
        self.network_input = QLineEdit()
        self.network_input.setPlaceholderText("Enter network range (e.g., 192.168.1.0/24 or 192.168.1.100-110)")
        network_layout.addWidget(QLabel("Network Range:"))
        network_layout.addWidget(self.network_input)
        layout.addLayout(network_layout)
        
        # Geolocation inputs (only for public scans)
        self.geo_layout = QHBoxLayout()
        self.lat_input = QLineEdit()
        self.lat_input.setPlaceholderText("Target Latitude (e.g., 37.7749)")
        self.lon_input = QLineEdit()
        self.lon_input.setPlaceholderText("Target Longitude (e.g., -122.4194)")
        self.distance_input = QLineEdit()
        self.distance_input.setPlaceholderText("Max Distance (km, e.g., 100)")
        self.geo_layout.addWidget(QLabel("Latitude:"))
        self.geo_layout.addWidget(self.lat_input)
        self.geo_layout.addWidget(QLabel("Longitude:"))
        self.geo_layout.addWidget(self.lon_input)
        self.geo_layout.addWidget(QLabel("Distance (km):"))
        self.geo_layout.addWidget(self.distance_input)
        layout.addLayout(self.geo_layout)
        self.toggle_geo_inputs()
        
        # Connect radio buttons to toggle geolocation inputs
        self.private_radio.toggled.connect(self.toggle_geo_inputs)
        self.public_radio.toggled.connect(self.toggle_geo_inputs)
        
        # Buttons
        buttons_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Scan")
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.setEnabled(False)
        buttons_layout.addWidget(self.start_button)
        buttons_layout.addWidget(self.stop_button)
        layout.addLayout(buttons_layout)
        
        # Output display
        self.output_display = QTextEdit()
        self.output_display.setReadOnly(True)
        layout.addWidget(self.output_display)
        
        self.setLayout(layout)
        
        # Connect buttons
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
    
    def toggle_geo_inputs(self):
        is_public = self.public_radio.isChecked()
        self.lat_input.setEnabled(is_public)
        self.lon_input.setEnabled(is_public)
        self.distance_input.setEnabled(is_public)
    
    def start_scan(self):
        if self.scanning:
            QMessageBox.warning(self, "Warning", "Network scan is already in progress.")
            return
        
        network_range = self.network_input.text().strip()
        if not network_range:
            QMessageBox.warning(self, "Input Error", "Please enter a network range to scan.")
            return
        
        is_public = self.public_radio.isChecked()
        if is_public:
            try:
                target_lat = float(self.lat_input.text().strip())
                target_lon = float(self.lon_input.text().strip())
                max_distance_km = float(self.distance_input.text().strip())
                target_coords = (target_lat, target_lon)
            except ValueError:
                QMessageBox.warning(self, "Input Error", "Please enter valid latitude, longitude, and distance.")
                return
        else:
            target_coords = None
            max_distance_km = None
        
        self.scanning = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.output_display.clear()
        
        # Start scanning in a separate thread
        self.scan_thread = threading.Thread(target=self.perform_scan, args=(network_range, is_public, target_coords, max_distance_km))
        self.scan_thread.start()
    
    def stop_scan(self):
        self.scanning = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.output_display.append("Network scan stopped by user.")
    
    def perform_scan(self, network_range, is_public, target_coords, max_distance_km):
        nm = nmap.PortScanner()
        try:
            self.output_display.append(f"Starting scan of range {network_range}...")
            nm.scan(hosts=network_range, arguments='-sn')  # Ping scan
        except nmap.PortScannerError as e:
            self.output_display.append(f"Network scan error: {e}")
            self.scanning = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            return
        except Exception as e:
            self.output_display.append(f"Unknown error: {e}")
            self.scanning = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            return
    
        active_hosts = [host for host in nm.all_hosts() if nm[host].state() == 'up']
        self.output_display.append(f"Found {len(active_hosts)} active devices:")
        for ip in active_hosts:
            self.output_display.append(f"- {ip}")
    
        if not active_hosts:
            self.output_display.append("No active devices found. Ending scan.")
            self.scanning = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            return
    
        if not is_public:
            self.output_display.append("\nScan completed for private network.")
            self.scanning = False
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            return
    
        # Public network: perform geolocation filtering
        self.output_display.append("\nDetermining geolocation of devices and filtering by distance...")
        nearby_devices = []
        for idx, ip in enumerate(active_hosts, 1):
            if not self.scanning:
                break
            self.output_display.append(f"Processing {idx}/{len(active_hosts)}: {ip}")
            # Check if IP is public
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private:
                    self.output_display.append(f"IP address {ip} is private. Geolocation not available.")
                    continue
            except ValueError:
                self.output_display.append(f"Invalid IP address: {ip}")
                continue
    
            # Get geolocation
            url = f"http://ip-api.com/json/{ip}"
            try:
                response = requests.get(url, timeout=5)
                data = response.json()
                if data['status'] != 'success':
                    self.output_display.append(f"Failed to get geolocation for IP {ip}: {data.get('message', 'Unknown error')}")
                    continue
                device_coords = (data['lat'], data['lon'])
            except requests.RequestException as e:
                self.output_display.append(f"Error querying GeoIP service for IP {ip}: {e}")
                continue
    
            # Calculate distance
            distance = geodesic(target_coords, device_coords).kilometers
            if distance <= max_distance_km:
                nearby_devices.append((ip, distance))
                self.output_display.append(f" - {ip} is within {distance:.2f} km")
            else:
                self.output_display.append(f" - {ip} is {distance:.2f} km away")
    
            # Pause to respect API rate limits
            time.sleep(1.5)
    
        # Display nearby devices
        if nearby_devices:
            self.output_display.append(f"\nDevices within {max_distance_km} km of {target_coords}:")
            for ip, distance in nearby_devices:
                self.output_display.append(f"IP: {ip}, Distance: {distance:.2f} km")
        else:
            self.output_display.append(f"\nNo devices found within {max_distance_km} km of {target_coords}.")
    
        self.scanning = False
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
