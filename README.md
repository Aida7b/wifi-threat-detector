wifi-threat-detector tool by Aida

This is an open source Python tool for real time Wi-Fi security monitoring and threat detection. This tool detects suspicious wireless behavior such as unauthorized access point changes. When an anomaly is detected, it logs the event, sends an email alert, and visualizes the threat origin on a map using geolocation data.

Overview

Developed as part of a master's thesis in cybersecurity, this tool is designed to:

- Detect Evil Twin attacks or unauthorized AP switching by monitoring BSSID changes
- Identify public IP anomalies such as unexpected gateway IPs
- Geolocate attacker IPs (for example, from cloud VMs or foreign networks)
- Send real-time email alerts when a threat is detected
- Operate in the background with automatic monitoring

Features

- Real-time background monitoring of SSID and BSSID
- Logs suspicious Wi-Fi events in `network_log.txt`
- Sends email alerts with SSID, BSSID, public IP, and timestamp
- Maps the attack origin using IP geolocation on an interactive map
- Trusted network system to detect unauthorized APs
- Simple command-line interface for manual actions (map, logs, trust)

Files Created

- `network_log.txt` — Stores timestamped SSID, BSSID, and gateway IP logs
- `trusted_networks.json` — Stores known safe SSID/BSSID pairs
- `gateway_location_map.html` — Interactive map showing geolocated IP address

How to Use

Requirements

- Python 3.7 or higher
- Supported platforms: Windows, Linux, macOS

Installation

``` bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPO-NAME.git
cd YOUR-REPO-NAME
pip install -r requirements.txt
```

Running the Tool

```bash
python main.py
```
the app starts and we will be prompted to enter our email address to receive alerts.

Menu Options

| Option | Description |
|--------|-------------|
| [1] Geolocate Gateway IP and View Map | Displays current public IP location on a map |
| [2] View Logs | Shows the detection history from the log file |
| [3] Trust Current Network | Marks the current SSID and BSSID as trusted |
| [4] Exit | Closes the application |

Note: Background monitoring starts automatically at launch and continuously checks for AP or BSSID changes.

Email Alerts

Each alert includes:

- SSID and unexpected BSSID
- Gateway IP address
- Detection timestamp
- Geolocation link shown on the generated map

This tool uses a pre-configured Gmail account with an app specific password.

License

This project is licensed under the MIT License. You are free to use, modify, and distribute it.

Developer

- Name: Aida  
- Date: May 2025  
- Context: Master's Thesis in Cybersecurity
