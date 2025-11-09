# Network Logger
![PyPI](https://img.shields.io/pypi/pyversions/pyTelegramBotAPI?color=red)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/scapy)

## About logger
This logger logs Netrowk in fast_log (only with alerts), info_log(all packets, if turned on) and raw_log(with raw packets, if turned on) and has detailed settings with default_config.yaml or with users config.yaml files and of course flags. Also logger has ddos/dos detection,whitelist, Blackwall (blacklist with iptables), blacklist (that just hide ip's which in config file), and of course almost all setting may be turned on/off with flags or with config files.


## installation ways
In repasitory we've 3 version
1. Mono
2. With modules
3. Docker mono

## Usage/Installation mono version
1. Just create/download/clone "net_logger.py" file and install scapy with pipy if you in venv:
   ``` python
   pip install scapy
   ```
   or with apt:
   ```python
   sudo apt install python3-scapy
   ```

2. Create/download/clone default_config.yaml, there you've default settings with ddos detect enabled you can off that or configurate your own config file. for this download config.yaml, open with nano or what you want and configurate your own config file, how apply it to logger below with flags.
3. Run net_logger.py from directory where this file located
   ```
   sudo python3 net_logger.py
   ```

## Flags
```python
  -h or --help        #shows all flags and help information.
  -R or --real_time   #displays packets in real time.
  -H or --host_ip     #shows packets from your ip.
  -I or --info_log    #enable info logging for all packets.
  -raw or --raw_log   #enable raw logging for all packets.
  -W or --white_list  #enable whitelist for all ip's except that in config file.
  -B or --black_wall  #enable the Blackwall with iptables for ip's that in config file.
  --blacklist          #enable blacklist this list will hide ip's from realtime and logs.
  -ddos              #enable ddos detection.
  --config "route"    #enable user's config file.
```

## Logs
To view Logs in real time write:
```bash
 tail -f log_name.json
```
## Usage/Installation modules version
1. Create/download/clone all modules from repository in one folder.
2. Create/download/clone default_config.yaml and/or config.yaml.
   p.s configs for mono and configs for modules different and all guides included with configs.
3. Run net_logger.py from directory where this file located.
   ```
   sudo python3 net_logger.py
   ```
   P.s flags for modules version the same as for mono.

## Usage/Installation docker mono version
1. Create/download/clone "net_logger.py", "dockerfile" and "requirements" from repository.
2. Create docker from directory where this file located.
   ```
   docker build -t net_logger:latest .
   ```
3. And run it with this command
   ```
   docker run --rm -it \
   --name netlogger \
   --net=host \
   --cap-add=NET_RAW \
   --cap-add=NET_ADMIN \
   -v $(pwd)/logs:/app/net_logger_logs \
   net_logger:latest \
   -R
   ```
### Explanations
 ```
   docker run --rm -it \ <--- Run and delete after exit
   --name net_logger \ <--- Name for container
   --net=host \  <--- Access for host network
   --cap-add=NET_RAW \  <--- Access for creating raw sockets for scapy
   --cap-add=NET_ADMIN \ <--- Access that container enable to work with iptables
   -v $(pwd)/logs:/app/net_logger_logs \ <--- Folder for logs
   net_logger:latest \ <--- The image from which the container is created
   -R  <--- Flags which were mentioned above p.s flags the same as for the other
   ```

## Usege/Installation Telegram alerts bot
1. Create venv
   ```
   python3 -m venv venv
   ```
2. Enter venv
   ```
   source venv/bin/activate
   ```
3. Create/download/clone bot from repository to venv
4. Install aiogram
   ```
   pip install aiogram
   ```
5. Take bot token from BotFather in Telegram
6. Take your chat id from getmyid_bot
7. Put them in code
   ```python
   token = ""  #<--- your token bot that you got from BotFather
   chat_id = "" #<--- your chat id
   log = ""  #<--- your location "fast_log.json" with alerts
   ```

## Config files
```python
# default_config.yaml for IDS

#modules
real_time: false <--- #show packets in real time
logs_path: <--- #path for alert/info logs. example: /home/user/desktop/logs 
raw_path: <--- #path for raw logs. example: /home/user/desktop/logs p.s this works only with module version but if you put this in mono version code will work anyway.
raw_log: false <--- #enable raw logs for all packets
info_log: false <--- #enable info logs for all packets
host_ip: false <--- #show local/host ip in logs and if turn on realtime aslo in realtime
ddos: true <--- #enable ddos/dos detect
white_list: false <--- #enable whitelist p.s this list will send alert if detect ip that's not in the list.
black_wall: false <--- #enable Blackwall list p.s this list will drop ip's and work with iptables.
black_list: false <--- #enable blacklist p.s this list just won't show you ip's in realtime and in logs.
#settings for ddos module
window_size: 15 <--- #here window size for threshold in seconds
threshold: 1000 <--- #threshold for packets 
alert_cooldown: 5 <--- #alert cooldown for alerts it also causes for logs just for optimization
whitelist:
#example
 #- 192.168.0.15 <--- put here all your ip's and ip's thats not in whitelist will be dropped from logger, it's don't uses iptables.
  -
blackwall_list:
#example
 #- 192.168.0.25 <--- this blacklist it's use iptables for dropping ip's.
  -
blacklist_list:
#exmaple
 #- 192.168.0.63 <--- it's blacklist drops out packets and hide them in realtime and in logs.
  -
```
## A little bit explanations about logger
### Sniffing
1. Here happpening sniffing scapy sniff send packets to process_packet which passing through all modules, logging and pushing alerts if them enable.
```python
if __name__ == "__main__":
    if modules["black_list"] == True:
        atexit.register(cleanup_iptables)
        signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()

    print("starts sniffing packets... (ctrl+C for exit)")
    sniff(prn=process_packet, store=0, )
```
2. here we've daemon thread in background monitoring time window for packets and decreases the counters.
```python
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
```
