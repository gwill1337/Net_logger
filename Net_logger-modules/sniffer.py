from scapy.all import sniff, IP  # for sniffing NetWork
from scapy.layers.inet import TCP, UDP  # for recognize type port/protocol
from collections import Counter, deque
from datetime import datetime  # for current time
import socket, threading, time, os
import cli
import logger
import firewall

#this module for sniffing network and logging him if you picked flags for logging


_modules = None
_whitelist = None
_blackwall_list = None
_threshold = None
_window_size = None
_alert_cooldown = None
_raw_path = None
_blacklist_list = None

packet_counts = Counter()
timestamps = deque()
last_alert = {}
attacker_set = set()
lock = threading.Lock()

proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
port_map = {80: "HTTP", 443: "HTTPS", 53: "DNS"}

def init(modules, whitelist, blackwall_list, threshold, window_size, alert_cooldown, raw_path, blacklist_list):
    global  _modules, _whitelist, _blackwall_list, _threshold, _window_size, _alert_cooldown, _raw_path, _blacklist_list
    _modules = modules
    _whitelist = whitelist
    _blackwall_list = blackwall_list
    _threshold = threshold
    _window_size = window_size
    _alert_cooldown = alert_cooldown
    _raw_path = raw_path
    _blacklist_list = blacklist_list


    if _modules.get("raw_log"):
        os.makedirs(_raw_path, exist_ok=True)

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


def alerts(ip, count):
    return count > _threshold

def process_packet(packet):

    if _modules["raw_log"] == True:
        try:
            raw_path_log = os.path.join(_raw_path, "raw_log.json")
            decoded = packet.show(dump=True)
            with open(raw_path_log, "a", encoding="utf-8") as f:
                # current_time_raw_log = datetime.now().strftime("%H:%M:%S")
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


    if _modules["host_ip"] == False:
        try:
            Local_IP = socket.gethostbyname(socket.gethostname())
        except:
            Local_IP = None
        if Local_IP == src:
            return


    if _modules["white_list"] == True:
        if src not in _whitelist:
            return print(f"[ALERT]IP {src} in NetWork that's not in white list!!!")
        else:
            pass

    if _modules["black_list"] == True:
        if src in _blacklist_list:
            #print(f"[ok]IP {src} was dropped wih blacklist2!!!")
            return
        else:
            pass

    if _modules["black_wall"] == True:
        if src in _blackwall_list:
            logger.logger.info(f"IP {src} was dropped because he in the Blackwall.")
            return print(f"IP {src} was dropped because he in the Blackwall.")
        else:
            pass

    if _modules["info_log"] == True:
        logger.logger.info(f"Packet: {src} --> {dst}| Protocol: {proto_name}")

    if _modules["real_time"] == True and not in_attack:
        print(f"Packet: {src} -> {dst}| Protocol: {proto_name}")

    now = time.time()
    if _modules["ddos"] == True:  # and in_attack:

        # thread counts packets in real time
        with lock:
            packet_counts[src] += 1
            timestamps.append((now, src))
            count = packet_counts[src]
            last = last_alert.get(src, 0)

            if alerts(src, count):
                attacker_set.add(src)
            else:
                if src in attacker_set and count <= _threshold:
                    attacker_set.discard(src)

        last = last_alert.get(src, 0)
        if alerts(src, count) and now - last >= _alert_cooldown:
            current_time = datetime.now().strftime("%H:%M:%S")
            proto_name = get_proto_name(packet)
            logger.logger.warning(f"[ALERT] Detect DDoS/DoS attack from {src}: {count} packets in {_window_size} seconds"
                           f"With protocol: {proto_name}")
            print(f"[ALERT] Detect DDoS/DoS attack from {src}: {count} packets in {_window_size} seconds ")
            print(f"With protocol: {proto_name}| Time detect: {current_time}")
            last_alert[src] = now


# here also thread counts packets in attack and discard them if attack ended
def monitor():
    while True:
        time.sleep(1)
        now = time.time()
        with lock:
            while timestamps and now - timestamps[0][0] > _window_size:
                ts, ip = timestamps.popleft()
                packet_counts[ip] -= 1
                if packet_counts[ip] == 0:
                    del packet_counts[ip]
                if ip in attacker_set and packet_counts.get(ip, 0) <= _threshold:
                    attacker_set.discard(ip)
