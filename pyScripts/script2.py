import re
import csv
from datetime import datetime

# === Step 1: Load infected users ===
infected_users = {}
with open('infected_users.csv', 'r') as csvfile:
    reader = csv.DictReader(csvfile)
    for row in reader:
        email = row['email']
        infected_users[email] = {
            "ip": row['ip'],
            "mac": row['mac'],
            "infection_time": datetime.strptime(row['timestamp'], "%b %d %H:%M:%S"),
            "login_ips": set()
        }

# === Step 2: Parse mail.log ===
msg_id_to_sender = {}
activity_log = []

current_ip = None
current_ip_time = None

with open('mail.log', 'r') as logfile:
    for line in logfile:
        # Extract timestamp
        ts_match = re.match(r"([A-Z][a-z]{2} \d{2} \d{2}:\d{2}:\d{2})", line)
        if ts_match:
            current_ip_time = datetime.strptime(ts_match.group(1), "%b %d %H:%M:%S")

        # Extract current IP on connect
        ip_match = re.search(r"connect from unknown\[(.*?)\]", line)
        if ip_match:
            current_ip = ip_match.group(1)

        # Track sender and login IP
        from_match = re.search(r"(\w+): from=<(.+?)>", line)
        if from_match:
            msg_id, sender = from_match.groups()
            msg_id_to_sender[msg_id] = {
                "sender": sender,
                "timestamp": current_ip_time,
                "ip": current_ip
            }

            if sender in infected_users:
                if current_ip_time > infected_users[sender]["infection_time"]:
                    infected_users[sender]["login_ips"].add(current_ip)

        # Track recipient and log activity
        to_match = re.search(r"(\w+): to=<(.+?)>", line)
        if to_match:
            msg_id, recipient = to_match.groups()
            if msg_id in msg_id_to_sender:
                record = msg_id_to_sender[msg_id]
                sender = record["sender"]

                if sender in infected_users:
                    if record["timestamp"] > infected_users[sender]["infection_time"]:
                        activity_log.append({
                            "sender": sender,
                            "recipient": recipient,
                            "timestamp": record["timestamp"].strftime("%b %d %H:%M:%S"),
                            "from_ip": record["ip"],
                            "mac": infected_users[sender]["mac"]
                        })

# === Step 3: Write email activity output ===
with open('post_phish_email_activity.csv', 'w', newline='') as out_csv:
    fieldnames = ['sender', 'recipient', 'timestamp', 'from_ip', 'mac']
    writer = csv.DictWriter(out_csv, fieldnames=fieldnames)
    writer.writeheader()
    for entry in activity_log:
        writer.writerow(entry)

# === Step 4: Write login IPs per email ===
with open('infected_login_ips.csv', 'w', newline='') as ip_csv:
    writer = csv.writer(ip_csv)
    writer.writerow(['email', 'logged_in_ip'])
    for email, data in infected_users.items():
        for ip in data['login_ips']:
            writer.writerow([email, ip])

print("[+] Done!")
print("    → post_phish_email_activity.csv")
print("    → infected_login_ips.csv")
