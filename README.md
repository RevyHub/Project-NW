# NullWarden

![Python](https://img.shields.io/badge/python-3.13-blue) ![Status](https://img.shields.io/badge/status-active%20development-yellow)

A password-gated, modular command-line framework for network reconnaissance and forensics. NullWarden is intended for authorized security research, defensive verification, and incident-response practice on networks and systems you own or are explicitly permitted to test.

## Status

| Module | Status |
|---|---|
| Network forensics & recon | Completed |
| OSINT tooling | In progress |
| Security research toolbox | In progress |
| Remediation utilities | In progress |

## Features

- **Role-gated CLI** — password-protected entry with `Operator` and `BaseUser` roles, each with a different command set
- **Network forensics module**, including:
  - Local/public IP, hostname, CPU and memory reporting
  - ARP-based device discovery on the local subnet
  - Port scanning via `python-nmap`
  - Live packet capture via `scapy`
  - IP geolocation lookups
- Masked password entry (asterisk echo, backspace support) on both Windows and Unix
- All login attempts are timestamped and logged locally for audit purposes

## Requirements

- Python 3.10+
- [Nmap](https://nmap.org/) installed and on your `PATH` (for port scanning)
- Administrator/root privileges for ARP discovery and packet capture

```bash
pip install -r requirements.txt
```

Dependencies: `psutil`, `requests`, `rich`, `python-nmap`, `scapy`

## Usage

```bash
python app.py
```

You'll be prompted for a password, which determines your role and available commands:

```
[Operator Menu]                 [BaseUser Menu]
0 | Help                        0 | Help
1 | Network Forensics           1 | Network Forensics
2 | OSINT                       2 | OSINT
3 | ToolBox                     3 | ToolBox
4 | Hashing                     4 | Hashing
5 | Exit                        5 | Exit
7 | View Login Attempts
```

Inside the Network Forensics module:

```
CyberRecon> /host              # local/public IP, hostname, CPU & memory
CyberRecon> /scan              # ARP discovery of devices on your subnet
CyberRecon> /ports <IP>        # port scan a target
CyberRecon> /geo <IP>          # IP geolocation lookup
CyberRecon> /traffic           # live packet capture
CyberRecon> exit
```

## Project Structure

```
Project-NW/
  app.py
  requirements.txt
  NullWarden/
    core/
      auth.py         # role-gated login, password hashing, attempt logging
    network/
      recon.py        # host info, ARP scan, port scan, packet capture, geo lookup
    ui/
      banners.py       # CLI banners and screen helpers
```

## Known Issues

- The repository currently ships an `.ignore` file, which git does not recognize (it must be named `.gitignore`). As a result, `login_attempts.txt` has been committed to the repository along with real local login history. This file — and the file name — should be corrected, and the existing file should be removed from git history.

## Legal & Ethical Use

NullWarden is provided for lawful, authorized security research, defensive verification, incident-response exercises, and education only. You are solely responsible for ensuring you have explicit, documented authorization for any system or network on which you run this tool. The author does not endorse or support unauthorized or unlawful use.

Report security issues or policy concerns to the maintainer.
