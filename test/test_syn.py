from detection.syn_scan import detect_syn

base_time = 1000.0

# 模拟 20 个 SYN，只有 2 个 ACK
test_packets = []

for i in range(20):
    test_packets.append({
        "timestamp": base_time + i * 0.2,
        "src_ip": "10.0.0.9",
        "protocol": "TCP",
        "flags": "S"
    })

for i in range(2):
    test_packets.append({
        "timestamp": base_time + 1 + i,
        "src_ip": "10.0.0.9",
        "protocol": "TCP",
        "flags": "A"
    })

for packet in test_packets:
    alert = detect_syn(packet)
    if alert:
        print(alert)