#!/usr/bin/env python3
"""Synthetic Windows 4625 (failed logon) event generator.

Produces JSON-lines events shaped like a Splunk/Sentinel SecurityEvent feed so you can
test the password-spray detections without a live domain. Includes a clear spray pattern
from one attacker IP plus normal background noise.

Usage:
    python3 generate_sample_logs.py --out data/sample_4625.json --spray-ip 203.0.113.45
"""
import argparse
import json
import random
from datetime import datetime, timedelta, timezone

EVENT_ID = 4625
SUBNET_USERS = [f"user{i:03d}" for i in range(1, 61)]          # 60 real employees
SPRAY_TARGETS = [f"user{i:03d}" for i in range(1, 51)]          # spray hits 50 of them
NOISE_USERS = ["svc_backup", "svc_sql", "admin_jdoe", "kSmith"]


def make_event(ts: datetime, src: str, target: str, substatus: str = "0xc000006a") -> dict:
    return {
        "TimeGenerated": ts.isoformat(),
        "_time": ts.isoformat(),
        "EventID": EVENT_ID,
        "Computer": "DC01.corp.local",
        "IpAddress": src,
        "Workstation_Name": "UNK",
        "TargetUserName": target,
        "SubStatus": substatus,            # 0xc000006a = wrong password
        "LogonType": 3,                    # network
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/sample_4625.json")
    ap.add_argument("--spray-ip", default="203.0.113.45")
    ap.add_argument("--minutes", type=int, default=30)
    args = ap.parse_args()

    random.seed(42)
    base = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    events: list[dict] = []

    # --- Background noise: a few scattered failures from legit internal hosts ---
    for m in range(args.minutes):
        for _ in range(random.randint(0, 3)):
            ts = base + timedelta(minutes=m, seconds=random.randint(0, 59))
            src = random.choice(["10.0.0.50", "10.0.0.51", "192.168.1.20"])
            events.append(make_event(ts, src, random.choice(NOISE_USERS + SUBNET_USERS)))

    # --- The spray: attacker IP hits 50 distinct accounts in ~8 minutes ---
    spray_start = base + timedelta(minutes=5)
    for i, target in enumerate(SPRAY_TARGETS):
        ts = spray_start + timedelta(seconds=i * 10)   # ~8.3 min total
        events.append(make_event(ts, args.spray_ip, target))

    events.sort(key=lambda e: e["TimeGenerated"])
    with open(args.out, "w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    print(f"wrote {len(events)} events to {args.out}")
    print(f"spray source {args.spray_ip} targeted {len(SPRAY_TARGETS)} distinct accounts")


if __name__ == "__main__":
    main()
