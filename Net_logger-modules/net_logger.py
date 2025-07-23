import atexit, signal, sys, threading  # for better customization and for direct work with the kernel
from scapy.all import sniff, IP  # for sniffing NetWork

from cli import config
from logger import logger
import sniffer
import firewall
import logger
from logger import logger as lg

#this main module with "__name__"
#also here all attributes from module "cli.py" imports to other modules with func init


def init():
    modules, window_size, threshold, alert_cooldown, whitelist, blackwall_list, logs_path, raw_path, blacklist_list = config()
    try:
        firewall.init(modules, blackwall_list)
    except AttributeError:
        pass
    try:
        sniffer.init(modules, whitelist,blackwall_list, threshold, window_size, alert_cooldown, raw_path, blacklist_list)

    except AttributeError:
        pass
    try:
        logger.init(modules, logs_path)
    except AttributeError:
        pass
    return  modules, window_size, threshold, alert_cooldown, whitelist, blackwall_list,logs_path ,raw_path , blacklist_list

def main():
    modules, window_size, threshold, alert_cooldown, whitelist, blackwall_list,logs_path ,raw_path, blacklist_list = init()
    if modules["black_wall"] == True:
        firewall.apply_blacklist()
        atexit.register(firewall.cleanup_iptables)
        signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    monitor_thread = threading.Thread(target=sniffer.monitor, daemon=True)
    monitor_thread.start()

    print("starts sniffing packets... (ctrl+C for exit)")
    sniff(prn=sniffer.process_packet, store=0, )

if __name__ == "__main__":
    main()
