import json
import sys
from collections import Counter

LOG = sys.argv[1] if len(sys.argv) > 1 else "logs/cowrie.json"

events, ips, users, passwords, commands, hours = (
    Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
)
logins = 0

with open(LOG) as f:
    for line in f:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        events[e.get("eventid", "unknown")] += 1
        if e.get("src_ip"):
            ips[e["src_ip"]] += 1
        if e.get("eventid", "").startswith("cowrie.login"):
            logins += 1
            users[e.get("username", "?")] += 1
            passwords[e.get("password", "?")] += 1
        if e.get("eventid") == "cowrie.command.input":
            commands[e.get("input", "")] += 1
        ts = e.get("timestamp", "")
        if len(ts) >= 13:
            hours[ts[11:13] + ":00"] += 1


def show(title, counter, n=10):
    print(f"\n=== {title} ===")
    for k, v in counter.most_common(n):
        print(f"{v:>5}  {k}")


print(f"Total login attempts: {logins}")
show("Event types", events)
show("Source IPs", ips)
show("Top usernames", users)
show("Top passwords", passwords)
show("Top commands", commands)
show("Activity by hour (UTC)", hours, 24)
