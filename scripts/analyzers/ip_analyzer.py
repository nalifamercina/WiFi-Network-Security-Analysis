from collections import Counter
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6


def analyze_ip_addresses(packets):

    source_ips = Counter()
    destination_ips = Counter()

    for packet in packets:

        if IP in packet:
            source_ips[packet[IP].src] += 1
            destination_ips[packet[IP].dst] += 1

        elif IPv6 in packet:
            source_ips[packet[IPv6].src] += 1
            destination_ips[packet[IPv6].dst] += 1

    return {
        "source_ips": source_ips,
        "destination_ips": destination_ips
    }