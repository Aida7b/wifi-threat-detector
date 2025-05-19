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

# === CONFIGURATION ===
LOG_FILE = "network_log.txt"
MONITOR_DURATION = 30  # seconds

# Gmail account that sends the alert
SENDER_EMAIL = "space.art0007@gmail.com"
SENDER_PASSWORD = "esugedhsjlukpqwm"  # app password without spaces

# === FUNCTIONS ===

def send_email_alert(ssid, gateway, timestamp, to_email):
    subject = "Wi-Fi Threat Detected"
    body = f"""
    Suspicious Wi-Fi Activity Detected

    Timestamp: {timestamp}
    SSID: {ssid}
    Gateway IP: {gateway}
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

def start_monitoring(receiver_email):
    print("\nStarting network monitoring...")
    start_time = time.time()

    while time.time() - start_time < MONITOR_DURATION:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ssid = get_ssid()
        gateway_ip = get_gateway_ip()

        log_entry = f"[{timestamp}] SSID: {ssid}, Gateway: {gateway_ip}"
        print(log_entry)

        with open(LOG_FILE, "a") as f:
            f.write(log_entry + "\n")

        send_email_alert(ssid, gateway_ip, timestamp, receiver_email)
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
    print("\nWi-Fi Threat Detection Tool")
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
