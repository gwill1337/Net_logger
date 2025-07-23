import argparse, yaml

#this module with flags and parsing default or user's config


def load_config(path):
    with open(path, "r") as f:
        return yaml.safe_load(f) or {}


def parse_args():
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

    return modules, cfg

def config():

    modules, cfg = parse_args()
    window_size = cfg.get("window_size", 15)
    threshold = cfg.get("threshold", 850)
    alert_cooldown = cfg.get("alert_cooldown", 5)

    logs_path = cfg.get("logs_path", "~/logs")
    raw_path = cfg.get("raw_path", "~/logs")
    # white/black lists
    whitelist = cfg.get("whitelist") or []
    blackwall_list = cfg.get("blackwall_list") or []
    blacklist_list = cfg.get("blacklist_list") or []
    return modules, window_size, threshold, alert_cooldown, whitelist, blackwall_list, logs_path, raw_path, blacklist_list
