from collections import Counter
from scapy.layers.dns import DNS, DNSQR


def analyze_dns(packets):

    dns_queries = Counter()

    for packet in packets:

        if packet.haslayer(DNSQR):

            domain = packet[DNSQR].qname.decode(errors="ignore")

            dns_queries[domain] += 1

    return dns_queries