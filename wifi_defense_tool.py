import time
import datetime
import os
import smtplib
import folium
import requests
import webbrowser
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess
import json
import threading
import psutil

# === CONFIGURATION ===
LOG_FILE = "network_log.txt"
MONITOR_INTERVAL = 10  # seconds

SENDER_EMAIL = "space.art0007@gmail.com"
SENDER_PASSWORD = "esugedhsjlukpqwm"

# === FUNCTIONS ===

def send_email_alert(subject, ip, timestamp, to_email):
    body = f"""
    Suspicious Activity Detected

    Timestamp: {timestamp}
    IP Address: {ip}
    Detected Behavior: Port Scanning or Suspicious Access
    """
    
    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        print(f"Email alert sent to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")

def get_gateway_ip():
    try:
        ip = requests.get("https://api.ipify.org").text
        return ip
    except:
        return "Unknown"

def get_ssid():
    try:
        result = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
        for line in result.splitlines():
            if "SSID" in line and "BSSID" not in line:
                return line.split(":")[1].strip()
    except Exception:
        return "Unknown"
    return "Unknown"

def get_bssid():
    try:
        result = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
        for line in result.splitlines():
            if "BSSID" in line:
                return line.split(":")[1].strip()
    except Exception:
        return "Unknown"
    return "Unknown"

def geolocate_ip(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        if res['status'] == 'success':
            lat = res['lat']
            lon = res['lon']
            city = res.get('city', 'Unknown')
            print(f"Gateway location: {city} ({lat}, {lon})")
            return lat, lon, city
    except Exception as e:
        print(f"Geolocation error: {e}")
    return None, None, "Unknown"

def generate_map(ip):
    lat, lon, city = geolocate_ip(ip)
    if lat and lon:
        m = folium.Map(location=[lat, lon], zoom_start=10)
        folium.Marker([lat, lon], tooltip=f"Gateway IP: {ip}\nCity: {city}").add_to(m)
        m.save("gateway_location_map.html")
        print("Map saved as gateway_location_map.html")
        webbrowser.open("gateway_location_map.html")
    else:
        print("Map generation failed.")

def check_if_trusted(ssid, bssid):
    if not os.path.exists("trusted_networks.json"):
        return False

    with open("trusted_networks.json", "r") as f:
        trusted = json.load(f)

    if ssid in trusted:
        expected_bssid = trusted[ssid]["bssid"]
        if bssid != expected_bssid:
            print(f"\nALERT: SSID '{ssid}' is trusted, but BSSID has changed!")
            print(f"Expected BSSID: {expected_bssid}, Current BSSID: {bssid}")
            return True
    else:
        print(f"\n'{ssid}' is not in your trusted network list.")
        return True
    return False

def background_monitor(receiver_email):
    print("\n[Background Monitoring Started]")
    last_bssid = get_bssid()

    # Start monitoring network connections for port scanning
    connection_monitor_thread = threading.Thread(target=monitor_connections, daemon=True)
    connection_monitor_thread.start()

    while True:
        ssid = get_ssid()
        bssid = get_bssid()
        gateway_ip = get_gateway_ip()
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        alert_triggered = check_if_trusted(ssid, bssid)
        if alert_triggered:
            log_entry = f"[{timestamp}] ALERT: SSID: {ssid}, BSSID: {bssid}, Gateway: {gateway_ip}"
            with open(LOG_FILE, "a") as f:
                f.write(log_entry + "\n")
            print(log_entry)
            send_email_alert(ssid, gateway_ip, timestamp, receiver_email)

        time.sleep(MONITOR_INTERVAL)

def trust_current_network():
    ssid = get_ssid()
    bssid = get_bssid()
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        trusted = {}
        if os.path.exists("trusted_networks.json"):
            with open("trusted_networks.json", "r") as f:
                trusted = json.load(f)

        trusted[ssid] = {
            "bssid": bssid,
            "added_on": timestamp
        }

        with open("trusted_networks.json", "w") as f:
            json.dump(trusted, f, indent=4)

        print(f"\nTrusted network saved: {ssid} -> {bssid}")
    except Exception as e:
        print(f"Failed to trust current network: {e}")

def view_logs():
    print("\nLog contents:")
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            print(f.read())
    else:
        print("No logs found.")

def geolocate_gateway():
    print("\nGeolocating Gateway IP...")
    ip = get_gateway_ip()
    if ip != "Unknown":
        generate_map(ip)
    else:
        print("Gateway IP not found.")

# === Network Monitoring for Port Scanning ===
SUSPICIOUS_THRESHOLD = 5  # Number of different ports accessed within a short time

# Function to monitor network connections
def monitor_connections():
    connections = {}
    while True:
        # Get all active connections
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':  # Only consider established connections
                ip = conn.raddr.ip  # Remote address IP
                port = conn.raddr.port  # Remote address port

                # Track the number of connections per IP
                if ip not in connections:
                    connections[ip] = []
                connections[ip].append(port)

        # Detect suspicious activity: too many ports accessed in a short time (port scanning)
        for ip, ports in connections.items():
            if len(set(ports)) >= SUSPICIOUS_THRESHOLD:  # Detect multiple different ports accessed
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                log_entry = f"[{timestamp}] Suspicious port scan detected from IP: {ip}, Ports: {ports}"
                
                # Log and alert
                with open(LOG_FILE, "a") as f:
                    f.write(log_entry + "\n")
                print(log_entry)
                
                # Send alert email
                send_email_alert("Suspicious Port Scan", ip, timestamp, "your_receiver_email@example.com")
                
        time.sleep(MONITOR_INTERVAL)  # Monitor every few seconds

def main():
    print("\nWi-Fi Threat Detection Tool")
    receiver_email = input("Enter your email to receive threat alerts: ").strip()

    monitor_thread = threading.Thread(target=background_monitor, args=(receiver_email,), daemon=True)
    monitor_thread.start()

    while True:
        print("\nSelect an option:")
        print("[1] Geolocate Gateway IP and View Map")
        print("[2] View Logs")
        print("[3] Trust Current Network")
        print("[4] Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            geolocate_gateway()
        elif choice == "2":
            view_logs()
        elif choice == "3":
            trust_current_network()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
