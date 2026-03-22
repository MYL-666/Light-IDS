from port_scan import detect_port_scan

base_time = 1000.0

# 模拟同一个IP在10秒内访问多个不同端口
test_packets = [
    {"timestamp": base_time + 0, "src_ip": "10.0.0.5", "dst_port": 21, "protocol": "TCP"},
    {"timestamp": base_time + 1, "src_ip": "10.0.0.5", "dst_port": 22, "protocol": "TCP"},
    {"timestamp": base_time + 2, "src_ip": "10.0.0.5", "dst_port": 23, "protocol": "TCP"},
    {"timestamp": base_time + 3, "src_ip": "10.0.0.5", "dst_port": 25, "protocol": "TCP"},
    {"timestamp": base_time + 4, "src_ip": "10.0.0.5", "dst_port": 53, "protocol": "TCP"},
    {"timestamp": base_time + 5, "src_ip": "10.0.0.5", "dst_port": 80, "protocol": "TCP"},
    {"timestamp": base_time + 6, "src_ip": "10.0.0.5", "dst_port": 110, "protocol": "TCP"},
    {"timestamp": base_time + 7, "src_ip": "10.0.0.5", "dst_port": 139, "protocol": "TCP"},
    {"timestamp": base_time + 8, "src_ip": "10.0.0.5", "dst_port": 443, "protocol": "TCP"},
    {"timestamp": base_time + 9, "src_ip": "10.0.0.5", "dst_port": 8080, "protocol": "TCP"},
]

for packet in test_packets:
    alert = detect_port_scan(packet)
    if alert:
        print(alert)