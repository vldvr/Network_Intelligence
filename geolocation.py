from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox
import requests
import socket

class GeolocationWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        
        # Input for domain or IP
        input_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("Enter domain or IP address")
        self.get_button = QPushButton("Get Geolocation")
        
        input_layout.addWidget(QLabel("Target:"))
        input_layout.addWidget(self.target_input)
        input_layout.addWidget(self.get_button)
        
        layout.addLayout(input_layout)
        
        # Output display
        self.output_display = QTextEdit()
        self.output_display.setReadOnly(True)
        layout.addWidget(self.output_display)
        
        self.setLayout(layout)
        
        # Connect button
        self.get_button.clicked.connect(self.get_geolocation)
    
    def get_geolocation(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Error", "Please enter a domain or IP address.")
            return
        
        # Resolve domain to IP if necessary
        try:
            socket.inet_aton(target)
            ip = target
        except socket.error:
            try:
                ip = socket.gethostbyname(target)
            except socket.gaierror:
                QMessageBox.critical(self, "Error", f"Invalid domain name: {target}")
                return
        
        # Fetch geolocation data
        url = f"http://ip-api.com/json/{ip}"
        try:
            response = requests.get(url, timeout=5)
            data = response.json()
            if data["status"] == "fail":
                QMessageBox.critical(self, "Error", "Unable to determine geographical location.")
                return
            latitude = data["lat"]
            longitude = data["lon"]
            city = data["city"]
            country = data["country"]
            self.output_display.setText(
                f"Geographical location: {city}, {country}\n"
                f"Latitude: {latitude}\n"
                f"Longitude: {longitude}"
            )
        except requests.RequestException as e:
            QMessageBox.critical(self, "Error", f"Error fetching geolocation: {e}")
