from detection.brute_force import detect_bruteforce

base_time = 1000.0

test_packets = []

# 模拟同一个IP疯狂连SSH
for i in range(15):
    test_packets.append({
        "timestamp": base_time + i * 1,
        "src_ip": "10.0.0.8",
        "protocol": "TCP",
        "dst_port": 22
    })

for pkt in test_packets:
    alert = detect_bruteforce(pkt)
    if alert:
        print(alert)