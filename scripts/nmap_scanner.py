import nmap

scanner = nmap.PortScanner()

print("=" * 60)
print("Network Discovery & Port Scanner")
print("=" * 60)

# Discover active devices
scanner.scan(hosts="192.168.1.0/24", arguments="-sn")

devices = scanner.all_hosts()

print(f"\nDevices Found : {len(devices)}")

print("\nScanning Open Ports...\n")

for host in devices:

    print("=" * 60)

    print(f"IP Address : {host}")

    # Second scan for ports
    port_scan = nmap.PortScanner()

    port_scan.scan(host, arguments="-F")

    addresses = scanner[host].get("addresses", {})

    mac = addresses.get("mac", "Unknown")

    print(f"MAC Address : {mac}")

    vendor = scanner[host].get("vendor", {})

    if mac in vendor:
        print(f"Vendor      : {vendor[mac]}")
    else:
        print("Vendor      : Not Identified")

    print("\nOpen Ports")
    print("-" * 40)

    if host in port_scan.all_hosts():

        for protocol in port_scan[host].all_protocols():

            ports = port_scan[host][protocol].keys()

            for port in sorted(ports):

                state = port_scan[host][protocol][port]["state"]

                service = port_scan[host][protocol][port]["name"]
                product = port_scan[host][protocol][port].get("product", "")
                version = port_scan[host][protocol][port].get("version", "")

                service_info = f"{product} {version}".strip()

            if not service_info:
             service_info = "Version Not Available"

            print(f"{port:<8} {service:<15} {state:<8} {service_info}")

    print()