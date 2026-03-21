from scapy.layers.inet import IP, TCP, UDP

def parse_packet(packet):
    if IP not in packet:
        return None
    
    parsed={
        "timestamp": float(packet.time),
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": "OTHER",
        "src_port": None,
        "dst_port": None,
        "flags": None
    }
    
    if TCP in packet:
        parsed["protocol"] = "TCP"
        parsed["src_port"] = packet[TCP].sport
        parsed["dst_port"] = packet[TCP].dport
        parsed["flags"] = str(packet[TCP].flags)

    elif UDP in packet:
        parsed["protocol"] = "UDP"
        parsed["src_port"] = packet[UDP].sport
        parsed["dst_port"] = packet[UDP].dport

    return parsed

def format_packet_summary(packet_info):
    """
    Convert parsed packet into readable string.
    """

    if not packet_info:
        return "[PACKET] Non-IP or unsupported packet"

    return (
        f"[PACKET] {packet_info['protocol']} "
        f"{packet_info['src_ip']}:{packet_info['src_port']} -> "
        f"{packet_info['dst_ip']}:{packet_info['dst_port']} "
        f"flags={packet_info['flags']}"
    )