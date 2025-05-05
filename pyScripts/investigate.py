import csv
import json
from datetime import datetime
import pandas as pd

# Load infected users and convert timestamp
infected = pd.read_csv("infected_users.csv")

infected_info = {}  # key: IP → value: dict with email, mac, infection_time

for _, row in infected.iterrows():
    ip = row['ip']
    email = row['email']
    mac = row['mac']
    try:
        infection_time = datetime.strptime(row['timestamp'], "%b %d %H:%M:%S")
    except:
        continue

    infected_info[ip] = {
        "email": email,
        "mac": mac,
        "infection_time": infection_time
    }

# Prepare output
activity_logs = []
http_log_file = "http.log"

with open(http_log_file, "r") as f:
    for line in f:
        try:
            entry = json.loads(line)
            ip = entry.get("src_ip")
            timestamp_raw = entry.get("timestamp")

            if ip not in infected_info:
                continue

            # Parse and compare timestamps
            try:
                log_time = datetime.fromisoformat(timestamp_raw)
            except:
                continue

            if log_time > infected_info[ip]['infection_time']:
                activity_logs.append({
                    "email": infected_info[ip]['email'],
                    "ip": ip,
                    "mac": infected_info[ip]['mac'],
                    "timestamp": log_time.strftime("%b %d %H:%M:%S"),
                    "method": entry.get("http.http_method", ""),
                    "url": entry.get("http.url", ""),
                    "hostname": entry.get("http.hostname", ""),
                    "user_agent": entry.get("http.http_user_agent", "")
                })
        except json.JSONDecodeError:
            continue

# Output to CSV
output_file = "post_infection_activity.csv"
df = pd.DataFrame(activity_logs)
df.to_csv(output_file, index=False)
print(f"[+] Logged post-infection activity to {output_file}")
