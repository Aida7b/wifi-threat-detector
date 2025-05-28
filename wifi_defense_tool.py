import time
import datetime
import os
import smtplib
import folium
import requests
import webbrowser
import subprocess
import psutil
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# === CONFIGURATION ===
LOG_FILE = "network_log.txt"
MONITOR_DURATION = 30  # seconds

# Gmail account that sends the alert
SENDER_EMAIL = "space.art0007@gmail.com"
SENDER_PASSWORD = "esugedhsjlukpqwm"  # app password

SUSPICIOUS_PORTS = [21, 22, 23, 25, 3389, 4444, 5555, 8080, 31337]

# === FUNCTIONS ===

def send_email_alert(ssid, gateway, timestamp, to_email, extra_message=""):
    subject = "Wi-Fi/Port Threat Detected"
    body = f"""
Suspicious Activity Detected

Timestamp: {timestamp}
SSID: {ssid}
Gateway IP: {gateway}

{extra_message}
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
        return requests.get("https://api.ipify.org").text
    except:
        return "Unknown"

def get_ssid():
    try:
        result = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
        for line in result.splitlines():
            if "SSID" in line and "BSSID" not in line:
                return line.split(":")[1].strip()
    except:
        return "Unknown"
    return "Unknown"

def geolocate_ip(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        if res['status'] == 'success':
            return res['lat'], res['lon'], res.get('city', 'Unknown')
    except:
        pass
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

def detect_suspicious_ports():
    suspicious_found = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN' and conn.laddr.port in SUSPICIOUS_PORTS:
            suspicious_found.append(conn.laddr.port)
    return suspicious_found

def start_monitoring(receiver_email):
    print("\nStarting network and port monitoring...")
    start_time = time.time()

    while time.time() - start_time < MONITOR_DURATION:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ssid = get_ssid()
        gateway_ip = get_gateway_ip()

        log_entry = f"[{timestamp}] SSID: {ssid}, Gateway: {gateway_ip}"
        print(log_entry)

        suspicious_ports = detect_suspicious_ports()
        port_alert = ""

        if suspicious_ports:
            port_alert = f"Suspicious ports open: {', '.join(map(str, suspicious_ports))}"
            log_entry += f", {port_alert}"
            print(f"ALERT: {port_alert}")

        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")

        send_email_alert(ssid, gateway_ip, timestamp, receiver_email, port_alert)
        time.sleep(10)

    print("\nMonitoring stopped.")

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

def main():
    print("\nWi-Fi & Port Threat Detection Tool")
    receiver_email = input("Enter your email to receive threat alerts: ").strip()

    while True:
        print("\nSelect an option:")
        print("[1] Start Monitoring")
        print("[2] Geolocate Gateway IP and View Map")
        print("[3] View Logs")
        print("[4] Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            start_monitoring(receiver_email)
        elif choice == "2":
            geolocate_gateway()
        elif choice == "3":
            view_logs()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
