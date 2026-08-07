# Password Spray Detection Lab

A runnable lab for catching **password-spray attacks** against Windows Active Directory.
No production domain needed. It ships with Sigma, Splunk (SPL), and Microsoft Sentinel (KQL)
detections, a synthetic 4625 log generator, and a Docker Compose stack.

This is one of three labs I built as proof I can do SOC detection work, not just talk about it.
The other two are `vpn-anomaly-detection` and `splunk-detection-lab`.

## What a password spray actually is

A spray flips the brute-force axis. Instead of hammering one account with a thousand
passwords, the attacker takes one or two common passwords and fires them at hundreds of
accounts. The point is to stay under the per-account lockout limit and hide in the normal
noise of failed logons.

MITRE ATT&CK: [T1110.003 Brute Force: Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

## Why SOC analysts care

Locking out a single account is loud. A spray spreads the pain across the whole user base,
so no individual account trips its lockout threshold, but the *source IP* lights up.

The signal is aggregation over a window, not one event. You need:
- failed logons (`4625`) grouped by **source IP / hostname**
- distinct **targeted accounts** per source
- a time-window threshold (I use > 10 distinct accounts in 10 minutes from one source)

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

The generator plants a spray from one IP (`203.0.113.45`) hitting 50 distinct accounts in
about 8 minutes, plus background noise. If your detection doesn't surface that IP, it's wrong.

## Detection logic (all three engines)

Flag a source when, within a 10-minute sliding window, it produces failed logons (`4625`)
against **>= 10 distinct target accounts** from a single source IP/host. Tune the threshold
to your environment. Set it too low and a helpdesk subnet looks like an attack.

## Tuning notes

- **Service accounts / batch jobs** generate legit high-volume failures. Allowlist them.
- **VPN / NAT egress** collapses many users behind one IP. Correlate with the VPN session
  log (see the sibling `vpn-anomaly-detection` repo) before you alert.
- **False positive:** a stray `4625` storm after a company-wide password change mimics a
  spray. Require distinct-account count, not raw failure count.

## Visual

See `architecture.svg` for how this lab fits the broader detection portfolio.

## Author

Hemanth Kori. Built as part of a SOC analyst home-lab portfolio. Maps to MITRE ATT&CK T1110.003.
