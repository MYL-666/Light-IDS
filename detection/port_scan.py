from collections import defaultdict,deque

window_second=10

port_threshold=10

port_history=defaultdict(deque)

def detect_port_scan(packet_info):
    src_ip=packet_info.get('src_ip')
    dst_port = packet_info.get("dst_port")
    timestamp = packet_info.get("timestamp")
    protocol = packet_info.get("protocol")

    if protocol not in {'TCP','UDP'}:
        return None
    
    if src_ip is None or dst_port is None or timestamp is None:
        return None

    history = port_history[src_ip]
    history.append((timestamp, dst_port))

    while history and timestamp - history[0][0] > window_second:
        history.popleft()
    unique_ports = {port for _, port in history}
    if len(unique_ports) >= port_threshold:
        return {
            "type": "PORT_SCAN",
            "severity": "medium",
            "src_ip": src_ip,
            "unique_ports": len(unique_ports),
            "window_seconds": window_second,
            "message": f"Possible port scan from {src_ip}: {len(unique_ports)} unique ports in {window_second}s"
        }

    return None