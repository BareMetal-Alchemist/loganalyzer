import json

logs = []

with open("../../forensics/http.log", "r") as file:
    for line in file:
        try:
            logs.append(json.loads(line))
            print(json.dumps(logs[0], indent=2))
        except json.JSONDecodeError:
            continue

