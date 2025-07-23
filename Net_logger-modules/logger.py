import logging, json, os  # for logging and config
from datetime import datetime  # for current time
from cli import config

_modules = None
_logs_path = None

#this logging module, raw packets are logging in sniffing module

# json logs
class JSONFormatter(logging.Formatter):
    def format(self, record):
        data = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        return json.dumps(data)


def init(modules, logs_path):
    global _modules, _logs_path
    _modules = modules
    _logs_path = logs_path

    log_dir = os.path.abspath(os.path.expanduser(logs_path))
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    fast_log_path = os.path.join(log_dir, "fast_log.json")
    info_log_path = os.path.join(log_dir, "info_log.json")

    logger = logging.getLogger("ids")
    logger.setLevel(logging.DEBUG)


    fmt = JSONFormatter()
    if _modules.get("info_log"):
        ih = logging.FileHandler(info_log_path, mode="a")
        ih.setLevel(logging.INFO)
        ih.setFormatter(fmt)
        logger.addHandler(ih)


    wh = logging.FileHandler(fast_log_path, mode="a")
    wh.setLevel(logging.WARNING)
    wh.setFormatter(fmt)
    logger.addHandler(wh)

logger = logging.getLogger("ids")
