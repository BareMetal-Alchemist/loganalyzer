import json
import csv
import time
from ipaddress import ip_address, IPv4Address
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError

input_file = "http.log"
output_file = "whois_output.csv"
seen_ips = set()

fields = ["ip", "asn", "asn_description", "country", "network_name"]

with open(output_file, mode='w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fields)
    writer.writeheader()

    with open(input_file, 'r') as f:
        for line in f:
            try:
                log = json.loads(line)
                for ip_key in ["src_ip", "dest_ip"]:
                    ip = log.get(ip_key)

                    # Skip if bad, duplicate, or private/reserved
                    if not ip or ip in seen_ips:
                        continue
                    if not isinstance(ip_address(ip), IPv4Address) or ip.startswith(("10.", "192.168.", "172.")):
                        continue

                    seen_ips.add(ip)

                    try:
                        obj = IPWhois(ip)
                        res = obj.lookup_rdap()

                        writer.writerow({
                            "ip": ip,
                            "asn": res.get("asn", ""),
                            "asn_description": res.get("asn_description", ""),
                            "country": res.get("network", {}).get("country", ""),
                            "network_name": res.get("network", {}).get("name", "")
                        })

                        print(f"✓ Looked up {ip}")
                        time.sleep(1)

                    except IPDefinedError:
                        print(f"Skipped reserved/bogon IP: {ip}")
                    except Exception as e:
                        print(f"✗ Error looking up {ip}: {e}")
                        continue
            except json.JSONDecodeError:
                continue

