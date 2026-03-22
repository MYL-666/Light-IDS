import json
import time
from datetime import datetime

# 冷却时间（秒）
COOLDOWN_SECONDS = 10

# 存储最近一次 alert 时间
# key = (type, src_ip)
last_alert_time = {}


def should_alert(alert):
    """
    Decide whether to emit alert based on cooldown.
    """

    key = (alert["type"], alert["src_ip"])
    now = time.time()

    if key not in last_alert_time:
        last_alert_time[key] = now
        return True

    if now - last_alert_time[key] >= COOLDOWN_SECONDS:
        last_alert_time[key] = now
        return True

    return False


def log_alert(alert, output_file="alerts.jsonl"):
    """
    Print + save alert if passes cooldown.
    """

    if not should_alert(alert):
        return

    # 加时间戳
    alert_record = dict(alert)
    alert_record["logged_at"] = datetime.utcnow().isoformat() + "Z"

    # 终端输出
    print(f"[ALERT] {alert_record['type']} | {alert_record['message']}")

    # 写文件（JSON Lines）
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(alert_record) + "\n")