# Password Spray Detection Lab

A self-contained, runnable lab for detecting **password-spray attacks** against Windows
Active Directory environments. It ships with Sigma, Splunk (SPL), and Microsoft Sentinel (KQL)
detections, a synthetic Windows Security log generator, and a Docker Compose stack so you can
test the detections end-to-end without touching a production domain.

## What is a password spray?

A password spray is a credential-based attack where the attacker tries a **small number of
common passwords against many different accounts** (flipping the axis of a traditional
brute-force: few passwords × many users, instead of many passwords × one user). The goal is to
stay under per-account lockout thresholds and blend in with normal failed-logon noise.

MITRE ATT&CK: [T1110.003 Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

## Why it matters for a SOC

- A single account locking out is noisy and obvious. A spray spreads attempts across the whole
  user base, so per-account failure counts stay low while the *source IP* failure count spikes.
- The signal is **aggregation over a window**, not a single event. Good triage needs:
  - failed logons (`4625`) grouped by **source IP / hostname**
  - distinct **targeted accounts** per source
  - time-window thresholds (e.g. > 10 distinct accounts in 10 minutes from one source)

## Repo layout

```
password-spray-detection-lab/
├── README.md
├── LICENSE
├── detections/
│   ├── sigma/windows_password_spray.yaml     # Sigma rule (vendor-neutral)
│   ├── splunk/password_spray.spl             # Splunk SPL search
│   └── sentinel/password_spray.kql           # Microsoft Sentinel KQL
├── data/
│   └── generate_sample_logs.py               # synthetic 4625 event generator
├── docker-compose.yml                        # optional Splunk-free local runner
└── requirements.txt
```

## Quick start

```bash
# 1. Create synthetic logs (Windows 4625 failed logons, incl. a spray pattern)
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python3 data/generate_sample_logs.py --out data/sample_4625.json --spray-ip 203.0.113.45

# 2. Validate the Sigma rule parses
python3 -c "import yaml,sys; print('sigma ok' if yaml.safe_load(open('detections/sigma/windows_password_spray.yaml')) else 'bad')"

# 3. Drop the JSON into Splunk / Sentinel and run the matching detection
```

## Detection logic (all three engines)

Flag a source when, within a 10-minute sliding window, it produces failed logons (`4625`) against
**>= 10 distinct target accounts** from a single source IP/host. Tune the threshold to your
environment — a helpdesk subnet will look spray-like if you set it too low.

## Tuning notes

- **Service accounts / batch jobs** generate legit high-volume failures — allowlist them.
- **VPN / NAT egress** collapses many users behind one IP — correlate with the VPN session log
  (see the sibling `vpn-anomaly-detection` repo) before alerting.
- **False positive:** a stray `4625` storm after a password change can mimic a spray. Require
  distinct-account count, not raw failure count.

## Author

Built as part of a SOC analyst home-lab portfolio. Maps to MITRE ATT&CK T1110.003.
