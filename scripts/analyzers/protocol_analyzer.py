from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP


def analyze_protocols(packets):

    protocol_summary = {
        "IPv4": 0,
        "IPv6": 0,
        "TCP": 0,
        "UDP": 0,
        "ARP": 0
    }

    for packet in packets:

        if IP in packet:
            protocol_summary["IPv4"] += 1

        if IPv6 in packet:
            protocol_summary["IPv6"] += 1

        if TCP in packet:
            protocol_summary["TCP"] += 1

        if UDP in packet:
            protocol_summary["UDP"] += 1

        if ARP in packet:
            protocol_summary["ARP"] += 1

    return protocol_summary