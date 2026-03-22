import argparse
from scapy.all import sniff, rdpcap
from parser.packet_capture import parse_packet, format_packet_summary
from detection.port_scan import detect_port_scan
from detection.syn_scan import detect_syn

def arg_parser():
    parser=argparse.ArgumentParser(description='Capture the pcap file and parsinn')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--live',action='store_true',help='Capture live traffic')
    group.add_argument('--pcap',type=str,help='Read packets from a pcap file')
    parser.add_argument('--iface',type=str,default=None,help='Network interface or live capture')
    return parser.parse_args()

def packet_process(packet):
    packet_info=parse_packet(packet)
    if packet_info is None:
        return 
    print(format_packet_summary(packet_info))

    alert = detect_port_scan(packet_info)
    if alert:
        print(f"[ALERT] {alert['message']}")

    syn_alert = detect_syn(packet_info)
    if syn_alert:
        print(f"[ALERT] {syn_alert['message']}")

def live_capture(interface=None):
    sniff(
        iface=interface,
        prn=packet_process,
        store=False,
        count=20
    )

def run_pcap_analysis(pcap_file):
    packets=rdpcap(pcap_file)
    for packet in packets:
        packet_process(packet)



def main():
    args=arg_parser()
    if args.live:
        live_capture(args.iface)
    elif args.pcap:
        run_pcap_analysis(args.pcap)
    else:
        print('Usage:')
        print("  python main.py --pcap sample.pcap")
        print("  sudo python main.py --live --iface en0")

if __name__ == '__main__':
    main()