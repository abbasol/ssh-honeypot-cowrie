import json
import sys
from collections import Counter

LOG = sys.argv[1] if len(sys.argv) > 1 else "logs/cowrie.json"

events, ips, users, passwords, commands, hours = (Counter() for _ in range(6))
sessions = 0
attempts = 0

with open(LOG) as f:
    for line in f:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        eid = e.get("eventid", "unknown")
        events[eid] += 1

        if eid == "cowrie.session.connect":
            sessions += 1
            ips[e.get("src_ip", "?")] += 1
            hours[e.get("timestamp", "")[11:13] + ":00"] += 1

        if eid in ("cowrie.login.success", "cowrie.login.failed") and "password" in e:
            attempts += 1
            users[e.get("username", "?")] += 1
            passwords[e.get("password", "?")] += 1

        if eid == "cowrie.command.input":
            for cmd in e.get("input", "").split(";"):
                cmd = cmd.strip()
                if cmd:
                    commands[cmd] += 1


def show(title, counter, n=10):
    print(f"\n=== {title} ===")
    for k, v in counter.most_common(n):
        print(f"{v:>5}  {k}")


print(f"Sessions: {sessions}")
print(f"Login attempts (with password): {attempts}")
show("Event types", events)
show("Source IPs (sessions)", ips)
show("Top usernames", users)
show("Top passwords", passwords)
show("Top commands", commands)
show("Sessions by hour (UTC)", hours, 24)
