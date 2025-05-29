import time
import datetime
import os
import smtplib
import requests
import folium
import webbrowser
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import sniff, IP, TCP, conf

# === CONFIGURATION ===
LOG_FILE = "port_attack_log.txt"
CHECK_INTERVAL = 10  # seconds
TRUSTED_FILE = "trusted_network.txt"
SENDER_EMAIL = "space.art0007@gmail.com"
SENDER_PASSWORD = "esugedhsjlukpqwm"  # app password
SUSPICIOUS_PORTS = [22, 23, 3389, 4444, 5555, 8080, 31337]
seen_sniffed_ips = set()

# === TRUSTED NETWORK LOGIC ===

def get_current_network_info():
    ssid = "Unknown"
    gateway = " "
    try:
        ssid_data = os.popen("netsh wlan show interfaces").read()
        for line in ssid_data.splitlines():
            if "SSID" in line and "BSSID" not in line:
                ssid = line.split(":")[1].strip()
                break

        ipconfig_data = os.popen("ipconfig").read()
        for line in ipconfig_data.splitlines():
            if "Default Gateway" in line:
                gateway = line.split(":")[1].strip()
                break
    except:
        pass
    return ssid, gateway

def save_current_as_trusted():
    ssid, gateway = get_current_network_info()
    with open(TRUSTED_FILE, "w") as f:
        f.write(f"{ssid}|{gateway}")
    print(f"✅ Trusted network saved: SSID = {ssid}, Gateway = {gateway}")

def is_trusted_network():
    if not os.path.exists(TRUSTED_FILE):
        return False
    try:
        trusted_ssid, trusted_gateway = open(TRUSTED_FILE).read().strip().split("|")
        current_ssid, current_gateway = get_current_network_info()
        return current_ssid == trusted_ssid and current_gateway == trusted_gateway
    except:
        return False

# === ALERT + GEO ===

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

This may indicate a scanning, brute-force, or DDoS-style flood.
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

# === MONITORING ===

def packet_sniffer(receiver_email, selected_iface):
    def process_packet(pkt):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            dport = pkt[TCP].dport
            if dport in SUSPICIOUS_PORTS:
                src_ip = pkt[IP].src
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                # NAT detection logic
                if src_ip == "192.168.1.1":  # Internal IP of the Fortinet firewall/router
                    try:
                        real_ip = requests.get("https://api.ipify.org").text.strip()
                        src_ip_note = f"{src_ip} (NAT gateway) — possible public attacker IP: {real_ip}"
                    except:
                        src_ip_note = f"{src_ip} (NAT gateway)"
                else:
                    src_ip_note = src_ip

                log_entry = f"[{timestamp}] Incoming packet to port {dport} from IP: {src_ip_note}"
                print(log_entry)
                with open(LOG_FILE, "a") as f:
                    f.write(log_entry + "\n")

                alert_key = f"{dport}-{src_ip}"
                if alert_key not in seen_sniffed_ips:
                    seen_sniffed_ips.add(alert_key)
                    map_file = generate_map(src_ip)
                    send_email_alert(timestamp, dport, src_ip_note, receiver_email, map_file)

    print(f"\n📡 Automatically sniffing on interface: {selected_iface}")
    sniff(filter="tcp", iface=selected_iface, prn=process_packet, store=0)

def start_monitoring(receiver_email):
    print("\n🔍 Continuous monitoring started. Press Ctrl+C to stop.\n")
    selected_iface = conf.iface
    print(f"📡 Automatically selected interface: {selected_iface}")

    sniff_thread = threading.Thread(target=packet_sniffer, args=(receiver_email, selected_iface), daemon=True)
    sniff_thread.start()

    try:
        while True:
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped by user.")

# === LOG VIEW ===

def view_logs():
    print("\n📜 Port Attack Logs:")
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            print(f.read())
    else:
        print("No logs found.")

# === MAIN MENU ===

def main():
    print("\n🚨 Suspicious Port Detection Tool")
    receiver_email = input("Enter your email to receive alerts: ").strip()

    while True:
        print("\nChoose an option:")
        print("[1] Start Monitoring (infinite)")
        print("[2] View Logs")
        print("[3] Save This Network as Trusted")
        print("[4] Exit")
        choice = input("Enter choice: ")

        if choice == "1":
            if is_trusted_network():
                print("✅ Connected to a trusted network. Monitoring skipped.")
            else:
                start_monitoring(receiver_email)
        elif choice == "2":
            view_logs()
        elif choice == "3":
            save_current_as_trusted()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
