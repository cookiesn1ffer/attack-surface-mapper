# Attack Surface Mapper

A subdomain enumeration and attack surface mapping tool with a desktop GUI. Discovers subdomains, scans ports, and fingerprints technologies — then generates a self-contained HTML report.

![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- **Subdomain enumeration** — certificate transparency logs via crt.sh + DNS brute force
- **Port scanning** — full 0–65535 scan via nmap with service/version detection
- **Tech fingerprinting** — HTTP headers, 50+ Wappalyzer-style patterns (WordPress, Next.js, Cloudflare, Stripe, etc.), TLS cert info
- **Desktop GUI** — dark-themed tkinter app with live output streaming
- **HTML report** — self-contained report saved at the end of every scan

---

## Requirements

- Python 3.9+
- [nmap](https://nmap.org/download.html) installed and on your PATH (required for port scanning)

---

## Installation

```bash
git clone https://github.com/cookiesn1ffer/attack-surface-mapper.git
cd attack-surface-mapper

python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # macOS/Linux

pip install -r requirements.txt
```

---

## Usage

### GUI (recommended)

```bash
python app.py
```

Enter your target domain, configure options in the sidebar, and hit **Start Scan**. Output streams live into the log panel. When the scan finishes, click **Open Report** to view the HTML report in your browser.

### Command line

```bash
python mapper.py example.com
```

**Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--wordlist FILE` | built-in (374 words) | Custom wordlist for DNS brute force |
| `--workers N` | 50 | Concurrent DNS resolver threads |
| `--no-brute` | — | Skip DNS brute force, use crt.sh only |
| `--no-ports` | — | Skip port scanning |
| `--no-fingerprint` | — | Skip tech fingerprinting |
| `--ports RANGE` | `1-65535` | Port range (e.g. `80,443` or `1-1024`) |
| `--limit N` | 0 (all) | Only scan the first N subdomains |
| `--output FILE` | `<domain>_report.html` | HTML report output path |

**Examples:**

```bash
# Quick recon — no port scan
python mapper.py example.com --no-ports

# crt.sh only, skip brute force
python mapper.py example.com --no-brute

# Scan specific ports only, limit to 10 subdomains
python mapper.py example.com --ports 80,443,8080,8443 --limit 10

# Use your own wordlist
python mapper.py example.com --wordlist /path/to/wordlist.txt
```

---

## Project Structure

```
attack-surface-mapper/
├── app.py               # Desktop GUI
├── mapper.py            # CLI entry point
├── requirements.txt
└── mapper/
    ├── subdomains.py    # crt.sh + DNS brute force
    ├── portscan.py      # nmap subprocess wrapper
    ├── fingerprint.py   # HTTP headers, patterns, TLS
    ├── reporter.py      # Terminal output + HTML report
    └── wordlist.txt     # Built-in subdomain wordlist
```

---

## Notes

- Port scanning requires nmap. If it's not installed, the port scan phase is skipped with an error message.
- Full 65535-port scans are slow by design. Use `--ports 80,443,8080,8443` for quick checks or `--limit N` to restrict how many subdomains get scanned.
- On Windows, run via `python app.py` rather than double-clicking — the app expects the virtual environment's Python.

---

## Disclaimer

This tool is for **authorized security testing only**. Only scan domains you own or have explicit written permission to test. Unauthorized scanning may be illegal in your jurisdiction.

---

## License

MIT
