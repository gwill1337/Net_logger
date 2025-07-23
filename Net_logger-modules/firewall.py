import subprocess
import cli

#this module for black/white list
#p.s blacklist works directly with kernel and whitelist only sends alerts if detect ip that's not in whitelist

_modules = None
_blackwall_list = None

def init(modules, blackwall_list):
    global _modules, _blackwall_list
    _modules = modules
    _blackwall_list = blackwall_list

def apply_blacklist():
    if _modules["black_wall"] == True:
        for ip in _blackwall_list:
            try:
                subprocess.run([
                    "iptables",
                    "-I", "INPUT",
                    "-s", ip,
                    "-j", "DROP"
                ], check=True)
                print("Blackwall enabled successful")
            except subprocess.CalledProcessError as e:
                (f"[ERROR] {e}")
    return

# and cleanup at exit
def cleanup_iptables():
    for ip in _blackwall_list:
        try:
            subprocess.run([
                "iptables",
                "-D", "INPUT",
                "-s", ip,
                "-j", "DROP"
            ], stderr=subprocess.DEVNULL)
            print(f"Removed {ip} from iptables")
        except Exception as e:
            print(f"Error removing {ip} from iptables: Error {e}")
