import argparse
from scapy.all import sniff, rdpcap
from parser.packet_capture import parse_packet, format_packet_summary
from detection.port_scan import detect_port_scan
from detection.syn_scan import detect_syn
from detection.brute_force import detect_bruteforce
from output.logger import log_alert

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

    alerts = [
        detect_port_scan(packet_info),
        detect_syn(packet_info),
        detect_bruteforce(packet_info)
    ]

    for alert in alerts:
        if alert:
            log_alert(alert)

def live_capture(interface=None):
    sniff(
        iface=interface,
        prn=packet_process,
        store=False,
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