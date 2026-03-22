from collections import defaultdict, deque

WINDOW_SECONDS = 30
ATTEMPT_THRESHOLD = 15

WATCHED_PORTS = {21, 22, 23, 3389}

attempt_history = defaultdict(deque)


def detect_bruteforce(packet_info):
    """
    Detect repeated connection attempts from the same source IP
    to the same sensitive port within a short time window.
    """

    src_ip = packet_info.get("src_ip")
    dst_port = packet_info.get("dst_port")
    timestamp = packet_info.get("timestamp")
    protocol = packet_info.get("protocol")

    if protocol != "TCP":
        return None

    if src_ip is None or dst_port is None or timestamp is None:
        return None

    if dst_port not in WATCHED_PORTS:
        return None

    key = (src_ip, dst_port)
    history = attempt_history[key]

    history.append(timestamp)

    while history and timestamp - history[0] > WINDOW_SECONDS:
        history.popleft()

    attempt_count = len(history)

    if attempt_count >= ATTEMPT_THRESHOLD:
        return {
            "type": "BRUTE_FORCE",
            "severity": "medium",
            "src_ip": src_ip,
            "target_port": dst_port,
            "attempts": attempt_count,
            "window_seconds": WINDOW_SECONDS,
            "message": (
                f"Possible brute-force from {src_ip} on port {dst_port}: "
                f"{attempt_count} attempts in {WINDOW_SECONDS}s"
            )
        }

    return None