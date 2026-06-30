from collections import Counter
from scapy.layers.inet import TCP, UDP


def analyze_ports(packets):

    source_ports = Counter()
    destination_ports = Counter()

    for packet in packets:

        if TCP in packet:

            source_ports[packet[TCP].sport] += 1
            destination_ports[packet[TCP].dport] += 1

        elif UDP in packet:

            source_ports[packet[UDP].sport] += 1
            destination_ports[packet[UDP].dport] += 1

    return {
        "source_ports": source_ports,
        "destination_ports": destination_ports
    }