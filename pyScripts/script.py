import pandas as pd
import json
from datetime import datetime

# Load the employee inventory
inventory = pd.read_csv('inventory.csv')  # Make sure it has 'Employee', 'IP', 'MAC' columns

# Prepare mappings
ip_to_email = {}
ip_to_mac = {}

for _, row in inventory.iterrows():
    full_name = str(row['Employee']).strip()
    ip = str(row['IP']).strip()
    mac = str(row['MAC']).strip()

    # Convert name to email
    try:
        first, last = full_name.split()
        email = f"{first[0].lower()}{last.lower()}@securetech.com"
    except ValueError:
        continue  # Skip malformed names

    ip_to_email[ip] = email
    ip_to_mac[ip] = mac

# Prepare output CSV
output_file = "infected_users.csv"
output_fields = ["email", "ip", "mac", "timestamp"]
output_rows = []

# Read and parse HTTP logs
with open("http.log", "r") as log_file:
    for line in log_file:
        try:
            entry = json.loads(line)

            # Filter by phishing indicators
            if (entry.get("http.http_method") == "POST" and
                entry.get("http.url") == "/login" and
                entry.get("dest_ip") == "23.74.164.69" and
                entry.get("http.hostname") == "srv-61.kim.johnson.biz"):

                src_ip = entry.get("src_ip")
                timestamp_raw = entry.get("timestamp")

                # Format timestamp
                try:
                    dt = datetime.fromisoformat(timestamp_raw)
                    formatted_time = dt.strftime("%b %d %H:%M:%S")  # "Feb 07 06:18:18"
                except:
                    formatted_time = timestamp_raw

                email = ip_to_email.get(src_ip, "unknown")
                mac = ip_to_mac.get(src_ip, "unknown")

                output_rows.append({
                    "email": email,
                    "ip": src_ip,
                    "mac": mac,
                    "timestamp": formatted_time
                })

        except json.JSONDecodeError:
            continue

# Save to CSV
output_df = pd.DataFrame(output_rows)
output_df.to_csv(output_file, index=False)
print(f"[+] Infected users exported to {output_file}")

