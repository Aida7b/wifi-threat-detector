import time
import datetime
import os
import smtplib
import psutil
import requests
import folium
import webbrowser
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import sniff, IP, TCP

# === CONFIGURATION ===
LOG_FILE = "port_attack_log.txt"
CHECK_INTERVAL = 10  # seconds
SENDER_EMAIL = "space.art0007@gmail.com"
SENDER_PASSWORD = "esugedhsjlukpqwm"  # app password
SUSPICIOUS_PORTS = [22, 23, 3389, 4444, 5555, 8080, 31337]
seen_sniffed_ips = set()

# === FUNCTIONS ===

def geolocate_ip(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        if res['status'] == 'success':
            return res['lat'], res['lon'], res.get('city', 'Unknown')
    except:
        pass
    return None, None, "Unknown"

def generate_map(ip, filename="attacker_map.html"):
    lat, lon, city = geolocate_ip(ip)
    if lat and lon:
        m = folium.Map(location=[lat, lon], zoom_start=10)
        folium.Marker([lat, lon], tooltip=f"Attacker IP: {ip}\nCity: {city}").add_to(m)
        m.save(filename)
        print(f"🌍 Map saved as {filename}")
        webbrowser.open(filename)
        return filename
    return None

def send_email_alert(timestamp, port, attacker_ip, to_email, map_file=None):
    subject = "Suspicious Port Activity Detected"
    body = f"""
⚠️ Suspicious Port Activity Detected

Timestamp: {timestamp}
Port: {port}
Remote IP: {attacker_ip}

This may indicate a scanning, brute-force or unauthorized access attempt.
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
        print(f"📧 Email alert sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email: {e}")

def detect_port_attacks():
    alerts = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status in ['LISTEN', 'ESTABLISHED'] and conn.laddr.port in SUSPICIOUS_PORTS:
            remote_ip = conn.raddr.ip if conn.raddr else "Unknown"
            alerts.append((conn.laddr.port, remote_ip))
    return alerts

def packet_sniffer(receiver_email):
    def process_packet(pkt):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            if dport in SUSPICIOUS_PORTS:
                src_ip = pkt[IP].src
                alert_key = f"{dport}-{src_ip}"
                if alert_key not in seen_sniffed_ips:
                    seen_sniffed_ips.add(alert_key)
                    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    log_entry = f"[{timestamp}] Incoming packet to port {dport} from IP: {src_ip}"
                    print(log_entry)
                    with open(LOG_FILE, "a") as f:
                        f.write(log_entry + "\n")

                    map_file = generate_map(src_ip)
                    send_email_alert(timestamp, dport, src_ip, receiver_email, map_file)

    print("📡 Starting packet sniffing...")
    sniff(filter="tcp", prn=process_packet, store=0)

def start_monitoring(receiver_email):
    print("\n🔍 Continuous monitoring started. Press Ctrl+C to stop.\n")
    seen_alerts = set()

    # Start background sniffing thread
    threading.Thread(target=packet_sniffer, args=(receiver_email,), daemon=True).start()

    try:
        while True:
            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            alerts = detect_port_attacks()

            for port, attacker_ip in alerts:
                alert_key = f"{port}-{attacker_ip}"
                if alert_key in seen_alerts:
                    continue
                seen_alerts.add(alert_key)

                log_entry = f"[{timestamp}] Suspicious on port {port}, remote IP: {attacker_ip}"
                print(log_entry)
                with open(LOG_FILE, "a") as f:
                    f.write(log_entry + "\n")

                map_file = None
                if attacker_ip != "Unknown":
                    map_file = generate_map(attacker_ip)

                send_email_alert(timestamp, port, attacker_ip, receiver_email, map_file)

            time.sleep(CHECK_INTERVAL)

    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user.")

def view_logs():
    print("\n📜 Port Attack Logs:")
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            print(f.read())
    else:
        print("No logs found.")

def main():
    print("\n🚨 Suspicious Port Detection Tool")
    receiver_email = input("Enter your email to receive alerts: ").strip()

    while True:
        print("\nChoose an option:")
        print("[1] Start Monitoring (infinite)")
        print("[2] View Logs")
        print("[3] Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            start_monitoring(receiver_email)
        elif choice == "2":
            view_logs()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
