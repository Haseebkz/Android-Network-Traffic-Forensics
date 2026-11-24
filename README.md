# Forensics Lab: Android Network Traffic Forensics

**Mobile Privacy Analysis | Pixel 9 Android Emulator | Wireshark | Python | Scapy**

focused on network forensics of Android mobile traffic captured from a Google Pixel 9 emulator.

## Project Overview

This project captures and analyzes Android network traffic to investigate background network connections, third-party tracking services, destination server IP addresses and domains, and potential mobile privacy leakage.

Traffic is captured with **Wireshark** and analyzed using a Python-based tool built with **Scapy**. The analysis helps identify which remote services an Android environment communicates with, including third-party tracking and advertising domains contacted in the background.

The project also examines traffic volume by measuring bytes uploaded and downloaded. These measurements provide evidence of the amount of network traffic exchanged; they do not, by themselves, reveal the exact personal information or payload content received by a vendor.

## Key Features

- Capture Android emulator network traffic using Wireshark.
- Analyze PCAP and PCAPNG files with Python and Scapy.
- Identify destination server IP addresses and domains.
- Detect tracker and advertising domains contacted in the background.
- Categorize detected tracker and advertising domains.
- Associate detected domains with known vendors and services where available.
- Measure uploaded and downloaded traffic volumes in bytes.
- Calculate per-source tracker scores and compare sources.
- Investigate suspicious network behaviour, including DGA-like domains, DNS tunnelling, beaconing, NXDOMAIN storms, cleartext PII indicators, direct-IP connections, exfiltration-like uploads, Tor/DoH/DoT traffic, and canary-string leakage.
- Generate HTML and XLSX reports, charts, and a GeoIP destination map.

## Tools & Technologies

| Tool / Technology | Purpose |
|---|---|
| Google Pixel 9 Android Emulator (AVD) | Test Android environment |
| Android Studio | Emulator setup |
| Wireshark | Network traffic capture |
| Python | Forensic analysis |
| Scapy | Packet parsing and analysis |
| PCAP / PCAPNG | Captured traffic file formats |
| MaxMind GeoLite2 | IP geolocation and ASN information |
| HTML / XLSX | Forensic report outputs |

## Lab Setup

| Component | Detail |
|---|---|
| Host | Windows 11 |
| Emulator | Android Studio, Pixel 9 AVD |
| Capture | Wireshark on the host (saved as PCAP) |
| Analysis | `scripts/netforensics.py` |

## Repository Structure

```text
Forensics_Lab/
├── scripts/
│   ├── netforensics.py     # Main analysis script
│   └── tracker_db.csv      # Disconnect + StevenBlack tracker list (auto-refreshed)
├── data/geoip/             # GeoLite2 .mmdb files (local only, git-ignored)
├── captures/
│   ├── raw/                # Real PCAPs (git-ignored)
│   └── samples/            # Small sanitized PCAPs
├── results/                # Generated outputs (git-ignored)
├── docs/
│   └── methodology.md
├── requirements.txt
└── README.md
```

## Setup

Install the required Python packages:

```bash
pip install -r requirements.txt
```

For GeoIP and ASN enrichment, download the free **GeoLite2-City.mmdb** and **GeoLite2-ASN.mmdb** databases from MaxMind (an account is required) and place them in `data/geoip/`.

These database files are not committed to the repository because of MaxMind's licensing terms.

## Usage

### Basic analysis

```bash
python scripts/netforensics.py captures/raw/new5.pcap -o results/new5
```

### Analysis with GeoIP, ASN, and canary-string search

```bash
python scripts/netforensics.py captures/raw/new5.pcap -o results/new5 \
  --geoip data/geoip/GeoLite2-City.mmdb --asn data/geoip/GeoLite2-ASN.mmdb \
  --canary "fake.test@mail.com,356938035643809"
```

### Split a capture into per-app time windows

```bash
python scripts/netforensics.py captures/raw/new5.pcap --markers
```

Add `--offline` to skip downloading tracker lists and use the cached `tracker_db.csv`.

## Privacy Analysis & Interpretation

The analysis highlights how Android applications and websites may establish background connections to third-party servers, including tracking and advertising infrastructure. It identifies destination IP addresses and domains, associates them with known vendors where possible, and measures the bytes exchanged.

**Important interpretation limits:**

- A packet capture can show that a connection occurred in the background. It cannot establish, on its own, whether the user gave consent or whether the connection was requested by the user.
- Uploaded and downloaded byte counts are evidence of traffic volume. They do not prove what exact data a vendor received or collected.
- Traffic is mostly encrypted with TLS/QUIC. The **“Data typically collected”** information in the report is inferred from vendor profiles, not confirmed from encrypted payloads.
- Confirming payload contents requires an appropriate TLS-decryption setup, such as `SSLKEYLOGFILE` or a controlled `mitmproxy` test environment.

## Project Objective

To demonstrate how network forensics can be used to identify background communications, investigate third-party tracking infrastructure, measure network data transfers, and assess potential privacy risks in Android environments.

## Ethics

Captures are collected from a test emulator only and are intended for educational and research purposes. No real personal data is used in the lab. Raw PCAP files are not committed to the repository.

## Credits

- Tracker lists: [Disconnect](https://disconnect.me/) and [StevenBlack hosts](https://github.com/StevenBlack/hosts)
- GeoIP and ASN data: [MaxMind GeoLite2](https://www.maxmind.com/en/geolite2-free-geolocation-data)
