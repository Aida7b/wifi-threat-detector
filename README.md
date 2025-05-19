# wifi-threat-detector tool -by Aida
This is a lightweight, open-source Python-based tool designed to monitor Wi-Fi activity, detect suspicious network behavior, and alert the user via email.  
It also performs geolocation of the gateway and visualizes it on an interactive map.
Overview
This project is developed as part of a master's thesis in cybersecurity.  
It detects potential wireless threats such as:
- Unexpected SSID changes
- Suspicious public IP gateways
- Unauthorized network rerouting
The tool logs this activity and can send email alerts with geolocation data.
Features
- Displays current SSID and public gateway IP
- Sends email alerts for suspicious connections
- Logs events in network_log.txt
- Shows geolocation of gateway on an interactive map
- Simple CLI interface with menu navigation
Planned future features:
- SSID spoofing detection
- Encryption downgrade alerts
- MAC address inconsistency tracking
- Deauthentication attack detection
- Trusted network verification
Files Created
network_log.txt - Stores timestamped SSID + public IP logs  
gateway_location_map.html - Interactive map showing gateway location
How to Use :
Python 3.7 or higher is required.
1. Clone the repository:
   git clone https://github.com/YOUR-USERNAME/YOUR-REPO-NAME.git
   cd YOUR-REPO-NAME
2. Install dependencies:
   pip install -r requirements.txt
3. Run the application:
   python main.py
4. Enter your email address to receive real-time alerts.
Menu Options
When running the program, you can choose:
[1] Start Monitoring
    - Logs SSID and public IP every 10 seconds
    - Sends alert emails to the configured address
[2] Geolocate Gateway IP and View Map
    - Uses public IP to generate a map of approximate router location
[3] View Logs
    - Displays contents of the log file
[4] Exit
    - Exits the tool
Email Alerts
The tool sends email alerts using a pre-configured Gmail account.  
Each alert contains:
- SSID of the Wi-Fi connection
- Public gateway IP address
- Timestamp of the detection
Note: The password used in the code is an app-specific Gmail password. Please replace it before public use if needed.
System Requirements
- Windows, Linux, or macOS
- Python 3.7+
- Internet connection (to fetch public IP, send emails, and display maps)
License
This project is licensed under the MIT License.  
You are free to use, modify, and distribute it.
Developer
Developed by: Aida
Date: May 2025
