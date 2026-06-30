def analyze_packet_sizes(packets):

    packet_sizes = [len(packet) for packet in packets]

    if not packet_sizes:
        return {
            "minimum": 0,
            "maximum": 0,
            "average": 0,
            "total_bytes": 0
        }

    return {
        "minimum": min(packet_sizes),
        "maximum": max(packet_sizes),
        "average": round(sum(packet_sizes) / len(packet_sizes), 2),
        "total_bytes": sum(packet_sizes)
    }