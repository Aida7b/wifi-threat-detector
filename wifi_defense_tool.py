"""
UNIVERSAL SUSPICIOUS-PORT DETECTION TOOL
––––––––––––––––––––––––––––––––––––––––
 • Works behind any brand of router / firewall.
 • Keeps your original packet-sniffer (good for labs) **and**
   adds three universal intakes that recover the real public
   attacker IP even when the edge device does SNAT:

     1.  Syslog traffic logs        (UDP/514)
     2.  NetFlow v5 collector       (UDP/2055)   ← toggle if you need it
     3.  REST / JSON log poller     (FortiGate, Palo Alto, Sophos, …)

 • Once an attacker IP is seen by *any* intake, the
   code geolocates it, saves a Folium map, e-mails you,
   and writes to `port_attack_log.txt`—exactly like before.

Edit only the CONFIGURATION section to fit your environment.
"""

# ======  STANDARD LIBS  ======
import os, time, datetime, threading, socket, struct, re, json, select
import smtplib, requests, folium, webbrowser
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ======  OPTIONAL: SCAPY LOCAL SNIFFER  ======
from scapy.all import sniff, IP, TCP, conf

# ---------------------------------------------------------------------------
#                               CONFIGURATION
# ---------------------------------------------------------------------------
LOG_FILE            = "port_attack_log.txt"
TRUSTED_FILE        = "trusted_network.txt"
CHECK_INTERVAL      = 10          # seconds between UI refreshes
SUSPICIOUS_PORTS    = {22, 23, 3389, 4444, 5555, 8080, 31337}

# -- Alerts ------------------------------------------------------------------
SENDER_EMAIL        = "your_gmail@gmail.com"
SENDER_PASSWORD     = "xxxxxx"                # Gmail “App Password”
GEOLocate_API       = "http://ip-api.com/json/"  # free, no key needed

# -- Universal Intake --------------------------------------------------------
LISTEN_IP           = "0.0.0.0"
SYSLOG_PORT         = 514         # works for every firewall that can log
ENABLE_NETFLOW      = False
NETFLOW_PORT        = 2055        # set True + this port if you use NetFlow

# REST pollers (leave empty if you rely on syslog/NetFlow)
POLL_INTERVAL       = 8           # seconds
VENDOR_REST = [
    # Example FortiGate; copy-paste & adjust for other vendors
    dict(
        name      = "FortiGate",
        url       = "https://192.0.2.1/api/v2/monitor/log/firewall",
        token     = "READ_ONLY_API_TOKEN",
        verify_ssl= False,
        src_key   = "srcip",
        port_key  = "dst_port",
        time_key  = "time"
    )
]

# ---------------------------------------------------------------------------
#                         TRUSTED NETWORK HELPERS
# ---------------------------------------------------------------------------
def _get_current_network_info():
    ssid, gateway = "Unknown", " "
    try:
        out = os.popen("netsh wlan show interfaces").read()
        for ln in out.splitlines():
            if "SSID" in ln and "BSSID" not in ln:
                ssid = ln.split(":", 1)[1].strip(); break
        out = os.popen("ipconfig").read()
        for ln in out.splitlines():
            if "Default Gateway" in ln:
                gateway = ln.split(":", 1)[1].strip(); break
    except: pass
    return ssid, gateway

def save_current_as_trusted():
    ssid, gw = _get_current_network_info()
    with open(TRUSTED_FILE, "w") as f: f.write(f"{ssid}|{gw}")
    print(f"✅ Trusted saved → SSID: {ssid}  GW: {gw}")

def _is_trusted():
    if not os.path.exists(TRUSTED_FILE): return False
    try:
        t_ssid, t_gw = open(TRUSTED_FILE).read().split("|")
        c_ssid, c_gw = _get_current_network_info()
        return t_ssid == c_ssid and t_gw == c_gw
    except: return False

# ---------------------------------------------------------------------------
#                           ALERT + GEOLOCATION
# ---------------------------------------------------------------------------
def _geolocate(ip):
    try:
        r = requests.get(GEOLocate_API + ip, timeout=5).json()
        if r["status"] == "success":
            return r["lat"], r["lon"], r.get("city","")
    except: pass
    return None, None, "Unknown"

def _make_map(ip):
    lat, lon, city = _geolocate(ip)
    if not lat: return None
    m = folium.Map(location=[lat,lon], zoom_start=10)
    folium.Marker([lat,lon], tooltip=f"{ip} – {city}").add_to(m)
    fname = f"map_{ip.replace('.','_')}.html"
    m.save(fname); webbrowser.open(fname)
    return fname

def _send_mail(ts, port, ip, to, mfile=None):
    body = f"""⚠ Suspicious port activity

Time   : {ts}
Port   : {port}
Source : {ip}
"""
    msg = MIMEMultipart(); msg["From"]=SENDER_EMAIL; msg["To"]=to
    msg["Subject"]="Suspicious Port Activity Detected"
    msg.attach(MIMEText(body,"plain"))
    try:
        with smtplib.SMTP("smtp.gmail.com",587) as s:
            s.starttls(); s.login(SENDER_EMAIL,SENDER_PASSWORD)
            s.send_message(msg)
        print(f"📧 Alert sent → {to}")
    except Exception as e:
        print("Email error:",e)

# ---------------------------------------------------------------------------
#                         UNIVERSAL INTAKE MODULE
# ---------------------------------------------------------------------------
_seen     = set()        # avoid duplicate alerts across intakes

# 1. Syslog ------------------------------------------------------------------
_sys_re = re.compile(r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*dstport=(?P<port>\d{1,5})')
def _syslog_listener(cb):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP,SYSLOG_PORT))
    while True:
        data,_=sock.recvfrom(4096)
        m=_sys_re.search(data.decode(errors="ignore"))
        if m:
            port=int(m['port'])
            if port in SUSPICIOUS_PORTS:
                cb(m['ip'],port,time.time())

# 2. NetFlow v5 (light) ------------------------------------------------------
def _parse_v5(pkt, cb):
    cnt=struct.unpack('!H',pkt[2:4])[0]; base=24
    for _ in range(cnt):
        rec=struct.unpack('!IIIHHBBBBHH',pkt[base:base+24])
        src='. '.join(map(str,rec[0].to_bytes(4,'big')))
        dst_port=rec[4]; proto=rec[6]
        if proto==6 and dst_port in SUSPICIOUS_PORTS:
            cb(src,dst_port,time.time())
        base+=24

def _netflow_listener(cb):
    sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.bind((LISTEN_IP,NETFLOW_PORT))
    while True:
        pkt,_=sock.recvfrom(8192)
        if len(pkt)>=24 and struct.unpack('!H',pkt[:2])[0]==5:
            _parse_v5(pkt,cb)

# 3. REST pollers ------------------------------------------------------------
def _rest_poller(cfg, cb):
    seen=set(); head={"Authorization":f"Bearer {cfg['token']}"}
    while True:
        try:
            r=requests.get(cfg['url'],headers=head,
                           verify=cfg.get('verify_ssl',True),timeout=5)
            for e in r.json().get("data",[]):
                ip=e[cfg['src_key']]; port=int(e[cfg['port_key']])
                ts=e[cfg['time_key']]
                key=(ip,port,ts)
                if key in seen or port not in SUSPICIOUS_PORTS: continue
                seen.add(key)
                cb(ip,port,time.time())
        except Exception as exc:
            print(f"[REST {cfg['name']}] error:",exc)
        time.sleep(POLL_INTERVAL)

# Shared callback ------------------------------------------------------------
def _handle_detection(ip, port, ts, receiver):
    key=f"{ip}:{port}"
    if key in _seen: return
    _seen.add(key)
    timestr=datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    log=f"[{timestr}] Port {port} hit from {ip}"
    print(log); open(LOG_FILE,"a").write(log+"\n")
    mapf=_make_map(ip)
    _send_mail(timestr,port,ip,receiver,mapf)

def start_universal_intake(receiver_email):
    cb=lambda ip,port,ts:_handle_detection(ip,port,ts,receiver_email)
    threading.Thread(target=_syslog_listener,args=(cb,),daemon=True).start()
    if ENABLE_NETFLOW:
        threading.Thread(target=_netflow_listener,args=(cb,),daemon=True).start()
    for cfg in VENDOR_REST:
        threading.Thread(target=_rest_poller,args=(cfg,cb),daemon=True).start()
    print("🌐 Universal intake running (syslog", 
          "+ netflow" if ENABLE_NETFLOW else "", 
          "+ REST x",len(VENDOR_REST),")")

# ---------------------------------------------------------------------------
#                     OPTIONAL LOCAL PACKET SNIFFER
# ---------------------------------------------------------------------------
def _sniff_local(receiver):
    iface=conf.iface
    print("📡 Local sniff on",iface)
    def _proc(pkt):
        if pkt.haslayer(IP) and pkt.haslayer(TCP):
            dport=pkt[TCP].dport
            if dport in SUSPICIOUS_PORTS:
                ip=pkt[IP].src
                _handle_detection(ip,dport,time.time(),receiver)
    sniff(filter="tcp",iface=iface,prn=_proc,store=0)

# ---------------------------------------------------------------------------
#                                UI
# ---------------------------------------------------------------------------
def _view_logs():
    if not os.path.exists(LOG_FILE):
        print("No logs yet."); return
    print("\n".join(open(LOG_FILE).read().splitlines()[-40:]))

def main():
    print("\n🚨 Universal Suspicious-Port Detector")
    recv=input("📧 Your e-mail for alerts: ").strip()
    while True:
        print("\n[1] Start monitoring\n[2] View logs\n[3] Save this Wi-Fi as trusted\n[4] Exit")
        ch=input("Choice: ")
        if ch=="1":
            if _is_trusted():
                print("✅ Trusted network—skipping monitor.")
                continue
            start_universal_intake(recv)
            threading.Thread(target=_sniff_local,args=(recv,),daemon=True).start()
            try:
                while True: time.sleep(CHECK_INTERVAL)
            except KeyboardInterrupt: print("\n🛑 Stopped.")
        elif ch=="2": _view_logs()
        elif ch=="3": save_current_as_trusted()
        elif ch=="4": break
        else: print("Invalid.")

if __name__=="__main__":
    main()
