import os
from scapy.all import rdpcap

# ==========================================
# Analyzer Modules
# ==========================================

from analyzers.protocol_analyzer import analyze_protocols
from analyzers.ip_analyzer import analyze_ip_addresses
from analyzers.packet_size_analyzer import analyze_packet_sizes
from analyzers.dns_analyzer import analyze_dns
from analyzers.port_analyzer import analyze_ports

# ==========================================
# Utility Modules
# ==========================================

from utils import PORT_NAMES
from report_generator import save_csv
from threat_detector import detect_threats
from graph_generator import save_bar_chart
from security_report import generate_security_report

# (We'll enable these after creating the modules)
# from graph_generator import save_bar_chart
# from nmap_scanner import scan_network


def main():

    print("=" * 60)
    print("WiFi Network Security Analyzer")
    print("=" * 60)

    # ==========================================
    # Locate Capture File
    # ==========================================

    project_root = os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    )

    pcap_file = os.path.join(
        project_root,
        "data",
        "capture_day1.pcapng"
    )

    # ==========================================
    # Read Packets
    # ==========================================

    packets = rdpcap(pcap_file)

    # ==========================================
    # Run Analysis Modules
    # ==========================================

    protocols = analyze_protocols(packets)

    ip_analysis = analyze_ip_addresses(packets)

    packet_sizes = analyze_packet_sizes(packets)

    dns_queries = analyze_dns(packets)

    port_analysis = analyze_ports(packets)

    # ==========================================
    # Threat Detection
    # ==========================================

    risk_level, findings, recommendations = detect_threats(
        protocols,
        dns_queries,
        port_analysis
    )

    # ==========================================
    # Basic Information
    # ==========================================

    print(f"\nCapture File : {os.path.basename(pcap_file)}")
    print(f"Total Packets : {len(packets)}")

    # ==========================================
    # Protocol Summary
    # ==========================================

    print("\nProtocol Summary")
    print("-" * 40)

    for protocol, count in protocols.items():
        print(f"{protocol:<10}: {count}")

    # ==========================================
    # Source IP Analysis
    # ==========================================

    print("\nTop 10 Source IP Addresses")
    print("-" * 40)

    for ip, count in ip_analysis["source_ips"].most_common(10):
        print(f"{ip:<40} {count}")

    # ==========================================
    # Destination IP Analysis
    # ==========================================

    print("\nTop 10 Destination IP Addresses")
    print("-" * 40)

    for ip, count in ip_analysis["destination_ips"].most_common(10):
        print(f"{ip:<40} {count}")

    # ==========================================
    # Packet Size Statistics
    # ==========================================

    print("\nPacket Size Statistics")
    print("-" * 40)

    print(f"Minimum Packet Size : {packet_sizes['minimum']} Bytes")
    print(f"Maximum Packet Size : {packet_sizes['maximum']} Bytes")
    print(f"Average Packet Size : {packet_sizes['average']} Bytes")
    print(f"Total Traffic       : {packet_sizes['total_bytes']} Bytes")

    # ==========================================
    # DNS Analysis
    # ==========================================

    print("\nTop DNS Queries")
    print("-" * 40)

    if dns_queries:

        for domain, count in dns_queries.most_common(10):
            print(f"{domain:<50} {count}")

    else:
        print("No DNS Queries Found.")

    # ==========================================
    # Source Ports
    # ==========================================

    print("\nTop Source Ports")
    print("-" * 40)

    for port, count in port_analysis["source_ports"].most_common(10):

        service = PORT_NAMES.get(port, "Unknown")

        print(f"{port:<8} {service:<15} {count}")

    # ==========================================
    # Destination Ports
    # ==========================================

    print("\nTop Destination Ports")
    print("-" * 40)

    for port, count in port_analysis["destination_ports"].most_common(10):

        service = PORT_NAMES.get(port, "Unknown")

        print(f"{port:<8} {service:<15} {count}")

    # ==========================================
    # Threat Detection Report
    # ==========================================

    print("\n" + "=" * 60)
    print("Threat Detection Report")
    print("=" * 60)

    print(f"\nOverall Risk Level : {risk_level}")

    print("\nFindings")
    print("-" * 40)

    for finding in findings:
        print(f"✓ {finding}")

    print("\nRecommendations")
    print("-" * 40)

    for recommendation in recommendations:
        print(f"• {recommendation}")

    # ==========================================
    # REPORT GENERATION
    # ==========================================

    print("\nGenerating Reports...")
    print("-" * 40)

    # ---------------- Protocol Summary ----------------

    protocol_rows = []

    for protocol, count in protocols.items():
        protocol_rows.append([protocol, count])

    save_csv(
        "protocol_summary.csv",
        ["Protocol", "Packets"],
        protocol_rows
    )

    # ---------------- Source IP Summary ----------------

    source_rows = []

    for ip, count in ip_analysis["source_ips"].most_common():
        source_rows.append([ip, count])

    save_csv(
        "source_ip_summary.csv",
        ["Source IP", "Packets"],
        source_rows
    )

    # ---------------- Destination IP Summary ----------------

    destination_rows = []

    for ip, count in ip_analysis["destination_ips"].most_common():
        destination_rows.append([ip, count])

    save_csv(
        "destination_ip_summary.csv",
        ["Destination IP", "Packets"],
        destination_rows
    )

    # ---------------- DNS Summary ----------------

    dns_rows = []

    for domain, count in dns_queries.most_common():
        dns_rows.append([domain, count])

    save_csv(
        "dns_summary.csv",
        ["Domain", "Queries"],
        dns_rows
    )

    # ---------------- Port Summary ----------------

    port_rows = []

    for port, count in port_analysis["destination_ports"].most_common():

        service = PORT_NAMES.get(port, "Unknown")

        port_rows.append([port, service, count])

    save_csv(
        "port_summary.csv",
        ["Port", "Service", "Packets"],
        port_rows
    )

    print("\nReports generated successfully.")

    # ==========================================
    # GRAPH GENERATION
    # ==========================================

    print("\nGenerating Graphs...")
    print("-" * 40)

    # Protocol Distribution

    save_bar_chart(
        "Protocol Distribution",
        list(protocols.keys()),
        list(protocols.values()),
        "protocol_distribution.png"
    )

    # Top Source IPs

    top_sources = ip_analysis["source_ips"].most_common(10)

    save_bar_chart(
        "Top Source IP Addresses",
        [ip for ip, _ in top_sources],
        [count for _, count in top_sources],
        "top_source_ips.png"
    )

    # Top Destination IPs

    top_destinations = ip_analysis["destination_ips"].most_common(10)

    save_bar_chart(
        "Top Destination IP Addresses",
        [ip for ip, _ in top_destinations],
        [count for _, count in top_destinations],
        "top_destination_ips.png"
    )

    # DNS Queries

    top_dns = dns_queries.most_common(10)

    save_bar_chart(
        "Top DNS Queries",
        [domain for domain, _ in top_dns],
        [count for _, count in top_dns],
        "dns_queries.png"
    )

    # Destination Ports

    top_ports = port_analysis["destination_ports"].most_common(10)

    save_bar_chart(
        "Destination Port Usage",
        [str(port) for port, _ in top_ports],
        [count for _, count in top_ports],
        "port_distribution.png"
    )

    print("\nGenerating Security Report...")
    print("-" * 40)

    generate_security_report(
        os.path.basename(pcap_file),
        len(packets),
        protocols,
        packet_sizes,
        findings,
        recommendations,
        risk_level
    )

    # ==========================================
    # PROGRAM COMPLETED
    # ==========================================

    print("\n" + "=" * 60)
    print("WiFi Network Security Analysis Completed Successfully!")
    print("=" * 60)

    print("\nGenerated Files:")
    print("✓ Protocol Report")
    print("✓ Source IP Report")
    print("✓ Destination IP Report")
    print("✓ DNS Report")
    print("✓ Port Report")

    print("\nReports saved in the 'reports' folder.")

    print("\nThank you for using WiFi Network Security Analyzer.")


# ==========================================
# Program Entry Point
# ==========================================

if __name__ == "__main__":
    main()