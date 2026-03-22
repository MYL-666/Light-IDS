from collections import defaultdict, deque

window_second=10
syn_threshold=20
ack_ratio_threshold=0.2

syn_stats=defaultdict(lambda:{"syn": deque(), "ack": deque()})

def detect_syn(packet_info):
    if packet_info.get("protocol") != "TCP":
        return None
    
    src_ip = packet_info.get("src_ip")
    flags = packet_info.get("flags")
    timestamp = packet_info.get("timestamp")

    if src_ip is None or flags is None or timestamp is None:
        return None
    
    stats = syn_stats[src_ip]

    if flags == "S":
        stats["syn"].append(timestamp)

    if "A" in flags:
        stats["ack"].append(timestamp)

    while stats["syn"] and timestamp - stats["syn"][0] > window_second:
        stats["syn"].popleft()

    while stats["ack"] and timestamp - stats["ack"][0] > window_second:
        stats["ack"].popleft()

    syn_count = len(stats["syn"])
    ack_count = len(stats["ack"])

    ack_ratio = (ack_count / syn_count) if syn_count > 0 else 0

    if syn_count >= syn_threshold and ack_ratio < ack_ratio_threshold:
            return {
            "type": "SYN_ANOMALY",
            "severity": "high",
            "src_ip": src_ip,
            "syn_count": syn_count,
            "ack_count": ack_count,
            "ack_ratio": round(ack_ratio, 2),
            "window_seconds": window_second,
            "message": (
                f"Possible SYN anomaly from {src_ip}: "
                f"SYN={syn_count}, ACK={ack_count}, ratio={ack_ratio:.2f}"
            )
        }
    
    return None