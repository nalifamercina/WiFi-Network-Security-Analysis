# ==========================================
# Threat Detection Module
# ==========================================

from utils import PORT_NAMES


def detect_threats(protocols, dns_queries, port_analysis):

    findings = []
    recommendations = []

    risk_level = "LOW"

    # ---------------------------------------
    # HTTPS Check
    # ---------------------------------------

    https_count = port_analysis["destination_ports"].get(443, 0)

    if https_count > 0:
        findings.append("HTTPS traffic detected.")
    else:
        findings.append("HTTPS traffic not detected.")
        risk_level = "MEDIUM"

    # ---------------------------------------
    # SMB Check
    # ---------------------------------------

    smb_count = port_analysis["destination_ports"].get(445, 0)

    if smb_count > 0:
        findings.append(
            f"SMB Service detected ({smb_count} packets)."
        )
        recommendations.append(
            "Disable SMB if file sharing is not required."
        )

    # ---------------------------------------
    # Telnet Check
    # ---------------------------------------

    telnet = port_analysis["destination_ports"].get(23, 0)

    if telnet > 0:

        findings.append("Warning: Telnet Port 23 Detected.")

        recommendations.append(
            "Replace Telnet with SSH."
        )

        risk_level = "HIGH"

    # ---------------------------------------
    # FTP Check
    # ---------------------------------------

    ftp = port_analysis["destination_ports"].get(21, 0)

    if ftp > 0:

        findings.append("FTP Service Detected.")

        recommendations.append(
            "Use SFTP instead of FTP."
        )

    # ---------------------------------------
    # Suspicious DNS
    # ---------------------------------------

    suspicious_extensions = [
        ".xyz",
        ".top",
        ".cyou",
        ".club",
        ".click"
    ]

    suspicious_domains = []

    for domain in dns_queries:

        for ext in suspicious_extensions:

            if ext in domain.lower():
                suspicious_domains.append(domain)

    if suspicious_domains:

        findings.append("Suspicious DNS Domains Found")

        for domain in suspicious_domains:
            findings.append(f"   -> {domain}")

        recommendations.append(
            "Review suspicious DNS domains."
        )

    else:

        findings.append("No suspicious DNS domains found.")

    # ---------------------------------------
    # Common Recommendation
    # ---------------------------------------

    recommendations.append(
        "Continue monitoring network traffic."
    )

    recommendations.append(
        "Use WPA2/WPA3 wireless security."
    )

    return risk_level, findings, recommendations