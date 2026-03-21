from scapy.all import IP, TCP
from packet_capture import parse_packet, format_packet_summary

# 构造一个假数据包（不用抓包也能测）
packet = IP(src="192.168.1.10", dst="192.168.1.1") / TCP(sport=12345, dport=80, flags="S")

parsed = parse_packet(packet)

print(parsed)
print(format_packet_summary(parsed))