# NetworkIntelligence

NetworkIntelligence is a Python-based GUI application that offers a suite of network tools, including:

- **Packet Sniffer**: Capture and filter network packets.
- **Traceroute**: Trace the path packets take to reach a destination.
- **Geolocation**: Retrieve the geographical location of a domain or IP address.
- **Network Scanner**: Scan network ranges to identify active devices, with optional geolocation filtering.

## **Features**

- User-friendly GUI built with PyQt5.
- Real-time packet logging with customizable filters.
- Perform traceroutes with detailed hop information.
- Fetch and display geolocation data for IPs or domains.
- Scan private and public networks, identifying active devices and filtering them based on distance from specified coordinates.

## **Installation**

### **Prerequisites**

- **Python 3.6+**
- **nmap** installed and accessible in your system's `PATH`.

### **Install Dependencies**

Use `pip` to install the required Python packages:

```
pip install -r requirements.txt
```
Install nmap
macOS (using Homebrew)
```
brew install nmap
```
Windows:

Download the installer from the official Nmap website and follow the installation instructions. Ensure that the installation directory is added to your system's PATH.

Running the Application
Navigate to the project directory and run:

```
python main.py
```
Note: Some functionalities, like packet sniffing and network scanning, may require administrator/root privileges.

macOS/Linux:

```
sudo python main.py
```
Windows:

Run the terminal (CMD or PowerShell) as an administrator and execute the script.

Usage
Upon launching the application, you'll be presented with a tabbed interface:

Packet Sniffer: Apply filters and start capturing packets. Logs are displayed in real-time and saved to filter_sniffer.log.
Traceroute: Enter a destination IP address to perform a traceroute.
Geolocation: Input a domain or IP to retrieve its geographical location.
Network Scanner: Choose to scan a private or public network range. For public scans, specify target coordinates and maximum distance to filter devices geographically.

Contributing
Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

License
MIT License

Contact
For any inquiries or support, please open an issue on the GitHub repository.
