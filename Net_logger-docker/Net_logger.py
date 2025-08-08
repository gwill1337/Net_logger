from scapy.all import sniff, IP  # for sniffing NetWork
from scapy.layers.inet import TCP, UDP  # for recognize type port/protocol
from collections import Counter, deque
from datetime import datetime  # for current time
import logging, json, yaml  # for logging and config
import argparse, atexit, signal, sys, subprocess, os  # for better customization and for direct work with the kernel
import socket, threading  # for recognize your host address and for threading
import time  # for time



def load_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


# arguments
modules = {k: False for k in (
    "real_time", "ddos", "white_list", "black_wall", "raw_log", "info_log", "host_ip", "black_list"
)}

parser = argparse.ArgumentParser(description="IDS")

parser.add_argument("-W", "--white_list", action="store_true",
                    help="Enable whitelist")
parser.add_argument("-raw", "--raw_log", action="store_true",
                    help="Enable logging raw packets")
parser.add_argument("-I", "--info_log", action="store_true",
                    help="Enable info logging")
parser.add_argument("-B", "--black_wall", action="store_true",
                    help="Enable blacklist/blackwall with iptables")
parser.add_argument("-R", "--real_time", action="store_true",
                    help="Enable real time view all packets")
parser.add_argument("-H", "--host_ip", action="store_true",
                    help="Show local/host ip in realtime and logs")
parser.add_argument("--blacklist", action="store_true",
                    help="Enable blacklist without iptables")
parser.add_argument("-ddos", action="store_true",
                    help="Enable blacklist without iptables")
parser.add_argument("--config", default="default_config.yaml", type=str,
                    help="Route for yaml config file")
args = parser.parse_args()

try:
    cfg_path = args.config
    cfg = load_config(cfg_path)
except FileNotFoundError:
    cfg = {}

for key, val in cfg.items():
    if key in modules:
        modules[key] = bool(val)

modules = {
        "real_time" : args.real_time or cfg.get("real_time", False),
        "white_list": args.white_list or cfg.get("white_list", False),
        "black_wall" : args.black_wall or cfg.get("black_wall", False),
        "raw_log" : args.raw_log or cfg.get("raw_log", False),
        "info_log" : args.info_log or cfg.get("info_log", False),
        "host_ip" : args.host_ip or cfg.get("host_ip", False),
        "black_list" : args.blacklist or cfg.get("black_list", False),
        "ddos" : args.ddos or cfg.get("ddos", False)
    }

# json logs
class JSONFormatter(logging.Formatter):
    def format(self, record):
        data = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        return json.dumps(data)

logs_path = cfg.get("logs_path", "~/logs")
log_dir = os.path.abspath(os.path.expanduser(logs_path))
os.makedirs(log_dir, exist_ok=True)

raw_path = cfg.get("raw_path", "~/logs")
log_raw_dir = os.path.abspath(os.path.expanduser(raw_path))
os.makedirs(log_dir, exist_ok=True)


fast_log_path = os.path.join(log_dir, "fast_log.json")
info_log_path = os.path.join(log_dir, "info_log.json")
raw_log_path = os.path.join(log_raw_dir, "raw_log.json")

logger = logging.getLogger("ids")
logger.setLevel(logging.DEBUG)
json_formatter = JSONFormatter()

info_handler = logging.FileHandler(info_log_path, mode="a")
info_handler.setLevel(logging.INFO)
info_handler.setFormatter(json_formatter)

warn_handler = logging.FileHandler(fast_log_path, mode="a")
warn_handler.setLevel(logging.WARNING)
warn_handler.setFormatter(json_formatter)
logger.addHandler(info_handler)
logger.addHandler(warn_handler)

# your host/local IP
try:
    Local_IP = socket.gethostbyname(socket.gethostname())
except:
    Local_IP = None

# proto map
proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
port_map = {80: "HTTP", 443: "HTTPS", 53: "DNS"}

# Ddos
window_size = cfg.get("window_size", 15)
threshold = cfg.get("threshold", 850)
alert_cooldown = cfg.get("alert_cooldown", 5)

# white/black lists
whitelist = cfg.get("whitelist", [])
blackwall_list = cfg.get("blackwall_list", [])
blacklist_list = cfg.get("blacklist_list", [])
#
packet_counts = Counter()
timestamps = deque()
last_alert = {}
attacker_set = set()
lock = threading.Lock()

# black list working direct with kernel
if modules["black_wall"] == True:
    for ip in blackwall_list:
        try:
            subprocess.run([
                "iptables",
                "-I", "INPUT",
                "-s", ip,
                "-j", "DROP"
            ], check=True)
            print("blackwall enabled successful")
        except subprocess.CalledProcessError as e:
            (f"[ERROR] {e}")


# and cleanup at exit
def cleanup_iptables():
    for ip in blackwall_list:
        try:
            subprocess.run([
                "iptables",
                "-D", "INPUT",
                "-s", ip,
                "-j", "DROP"
            ], stderr=subprocess.DEVNULL)
            print(f"Removed {ip} from iptables")
        except Exception as e:
            print(f"Error removing {ip} from iptables")


# alerts
def alerts(ip, count):
    return count > threshold


# getting protocol for logs
def get_proto_name(pkt):
    if pkt.haslayer(TCP):
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
        return proto_map.get(dport) or proto_map.get(sport) or proto_map[6]
    if pkt.haslayer(UDP):
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        return proto_map.get(dport) or proto_map.get(sport) or proto_map[17]

    num = pkt[IP].proto
    return proto_map.get(num, str(num))


# here all modules from config or if you put argument
def process_packet(packet):

    if modules["raw_log"] == True:
        try:
            decoded = packet.show(dump=True)
            with open(raw_log_path, "a", encoding="utf-8") as f:
                f.write("---------------------------------------------------")
                f.write(f"{datetime.now().strftime('%H:%M:%S')}")
                f.write(decoded + "\n")

        except Exception:
            pass

    if IP not in packet:
        return

    src = packet[IP].src
    dst = packet[IP].dst
    proto_name = get_proto_name(packet)
    in_attack = bool(attacker_set)

    if Local_IP and src == Local_IP and modules["host_ip"] == False:
        return

    if modules["info_log"] == True:
        logger.info(f"Packet: {src} --> {dst}| Protocol: {proto_name}")

    if modules["white_list"] == True:
        if src not in whitelist:
            print(f"[ALERT]IP {src} in NetWork that's not in white list!!!")
            return
        else:
            pass
    if modules["black_list"] == True:
        if src in blacklist_list:
            print(f"[ok]IP {src} was dropped with blacklist2")
            return
        else:
            pass

    if modules["black_wall"] == True:
        if src in blackwall_list:
            logger.info(f"IP {src} was dropped because he in the Blackwall.")
            return print(f"IP {src} was dropped because he in the Blackwall.")
        else:
            pass

    if modules["real_time"] == True and not in_attack:
        print(f"Packet: {src} -> {dst}| Protocol: {proto_name}")

    now = time.time()
    if modules["ddos"] == True:

        # thread counts packets in real time
        with lock:
            packet_counts[src] += 1
            timestamps.append((now, src))
            count = packet_counts[src]
            last = last_alert.get(src, 0)

            if alerts(src, count):
                attacker_set.add(src)
            else:
                if src in attacker_set and count <= threshold:
                    attacker_set.discard(src)

        last = last_alert.get(src, 0)
        if alerts(src, count) and now - last >= alert_cooldown:
            current_time = datetime.now().strftime("%H:%M:%S")
            proto_name = get_proto_name(packet)
            logger.warning(f"[ALERT] Detect DDoS/DoS attack from {src}: {count} packets in {window_size} seconds"
                           f"With protocol: {proto_name}")
            print(f"[ALERT] Detect DDoS/DoS attack from {src}: {count} packets in {window_size} seconds ")
            print(f"With protocol: {proto_name}| Time detect: {current_time}")
            last_alert[src] = now


# here also thread counts packets in attack and discard them if attack ended
def monitor():
    while True:
        time.sleep(1)
        now = time.time()
        with lock:
            while timestamps and now - timestamps[0][0] > window_size:
                ts, ip = timestamps.popleft()
                packet_counts[ip] -= 1
                if packet_counts[ip] == 0:
                    del packet_counts[ip]
                if ip in attacker_set and packet_counts.get(ip, 0) <= threshold:
                    attacker_set.discard(ip)


if __name__ == "__main__":
    if modules["black_wall"] == True:
        atexit.register(cleanup_iptables)
        signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()

    print("starts sniffing packets... (ctrl+C for exit)")
    sniff(prn=process_packet, store=0, )
