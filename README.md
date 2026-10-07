# Sentinel Firewall Policy Console

A local Python web app for inspecting IP-based firewall policy. Enter an IPv4 or IPv6 address to see the effective permission for each listed service, including port, protocol, matching rule, and default-deny decisions. Rules can be added or removed from the dashboard and are saved in `data/rules.json`.

## Run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in your browser. The server binds to loopback only.

## Policy behavior

- Rules match a source IP/CIDR, transport protocol, and destination port.
- Rules are evaluated from top to bottom; the first match decides `ALLOW` or `DENY`.
- New rules are inserted at the top. Unmatched traffic is denied by default.
- The starter policy allows selected SSH, DNS, HTTP, and HTTPS traffic from private ranges, blocks Telnet, and denies PostgreSQL from the sample LAN.

This is a policy simulator and dashboard, not a packet-filtering implementation. It does not inspect live traffic, configure Windows Defender Firewall, or modify any operating-system network settings. Do not expose the development server to an untrusted network.

## Tests

```powershell
python -m unittest discover -s tests -v
```