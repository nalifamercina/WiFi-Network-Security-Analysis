import os
from datetime import datetime


def generate_security_report(
    capture_file,
    packet_count,
    protocols,
    packet_sizes,
    findings,
    recommendations,
    risk_level
):

    report_folder = "reports"
    os.makedirs(report_folder, exist_ok=True)

    report_path = os.path.join(report_folder, "security_report.txt")

    with open(report_path, "w", encoding="utf-8") as report:

        report.write("=" * 70 + "\n")
        report.write("WiFi Network Security Analysis Report\n")
        report.write("=" * 70 + "\n\n")

        report.write(f"Generated On : {datetime.now()}\n")
        report.write(f"Capture File : {capture_file}\n")
        report.write(f"Total Packets: {packet_count}\n")
        report.write(f"Overall Risk : {risk_level}\n\n")

        report.write("-" * 70 + "\n")
        report.write("Protocol Summary\n")
        report.write("-" * 70 + "\n")

        for protocol, count in protocols.items():
            report.write(f"{protocol:<10}: {count}\n")

        report.write("\n")

        report.write("-" * 70 + "\n")
        report.write("Packet Statistics\n")
        report.write("-" * 70 + "\n")

        report.write(f"Minimum Packet Size : {packet_sizes['minimum']} Bytes\n")
        report.write(f"Maximum Packet Size : {packet_sizes['maximum']} Bytes\n")
        report.write(f"Average Packet Size : {packet_sizes['average']} Bytes\n")
        report.write(f"Total Traffic       : {packet_sizes['total_bytes']} Bytes\n\n")

        report.write("-" * 70 + "\n")
        report.write("Threat Findings\n")
        report.write("-" * 70 + "\n")

        for finding in findings:
            report.write(f"• {finding}\n")

        report.write("\n")

        report.write("-" * 70 + "\n")
        report.write("Recommendations\n")
        report.write("-" * 70 + "\n")

        for recommendation in recommendations:
            report.write(f"• {recommendation}\n")

        report.write("\n")

        report.write("=" * 70 + "\n")
        report.write("End of Report\n")
        report.write("=" * 70 + "\n")

    print(f"✓ Generated : {report_path}")