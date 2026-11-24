# Methodology

1. Start Pixel 9 emulator and a Wireshark capture on the host interface.
2. Visit each site/app, with a DNS marker lookup between them for auto-split (`--markers`).
3. Save the pcapng into `captures/raw/`.
4. Run `scripts/netforensics.py`; results go to `results/`.
5. Treat "Data typically collected" as inferred unless payloads are decrypted.
