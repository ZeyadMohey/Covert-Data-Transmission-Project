# Covert Data Transmission Project

A covert channel system that splits a secret message with **Shamir's Secret Sharing** and smuggles the shares across a LAN using two independent network-steganography techniques, so no single intercepted channel is enough to recover the message.

Graduation project, British University in Egypt (Networks) — individual work, grade 95/100.

## How it works

1. **Split** — the secret is split into 7 shares using Shamir's Secret Sharing over GF(2¹²⁷ − 1); any 4 of the 7 can reconstruct it, so losing up to 3 shares (dropped packets, a failed channel) doesn't lose the message.
2. **Tag** — each share gets an 8-character SHA-256 integrity tag, so the receiver can detect and discard a corrupted or tampered share before it's used in reconstruction.
3. **Split across channels** — 2 shares go out over an ARP-based channel, 5 over a TCP/IP-based channel, sent in parallel.
4. **Hide**
   - **ARP channel** (`lib/arp_steg.py`) — a modified ARPNetSteg. Data is XOR-encrypted and encoded into the *source MAC address* of ARP replies sent in response to the receiver's own ARP requests, cycling through a seeded, randomised list of unused IPs on the subnet.
   - **MTNS channel** (`lib/ip_steg.py`) — a modified Moving Target Network Steganography. The sender brute-forces random TCP payloads until the SHA-256 hash of the packet's metadata happens to encode the next data bits at seed-derived positions ("hash-bit marking"), so the bits are never written into the packet directly.
5. **Reconstruct** — the receiver collects shares from both channels, drops any that fail the integrity check, and reconstructs the secret with Lagrange interpolation once at least 4 valid shares have arrived. A TCP ACK is sent back to the sender on success.

Sender and receiver never exchange the IP list, XOR keys, or hash permutations directly — both sides derive them independently from a shared seed (`SEED_VALUE` in `lib/config.py`).

## Project layout

```
sender.py / receiver.py   Entry points (run one on each VM)
lib/
  secret_sharing.py        Shamir split / reconstruct (Lagrange interpolation)
  arp_steg.py               ARP-reply MAC covert channel
  ip_steg.py                 TCP/IP hash-bit-marking covert channel (MTNS)
  hashing.py                 SHA-256 share integrity tags
  config.py                  Shared constants (seed, IPs, ports, timeouts)
tests/                     36 pytest unit tests covering every module
metrics/                   Offline analysis: throughput, integrity, statistical detectability
  runner.py                  Drives all three analyses from captured .pcaps
  output/charts/             Generated comparison charts (PNG)
  output/results/            CSV results + summary_report.txt
```

## Running it

Requires two machines (or VMs) on the same LAN segment, raw-socket access (root), and Python with the packages in `requirements.txt` (built on Scapy).

```bash
pip install -r requirements.txt

# On the receiver VM
sudo python3 receiver.py

# On the sender VM, once the receiver says it's listening
sudo python3 sender.py
```

The sender prompts for a message, generates and hashes the shares, then waits for Enter before transmitting on both channels in parallel. `lib/config.py` holds the IPs, interface name and timeouts — update these to match your lab network before running.

### Tests

```bash
pytest
```

36 unit tests cover secret sharing (including tamper and threshold edge cases), both steganography channels, hashing, and the metrics modules.

### Metrics

Each run is captured to a `.pcap` and CSV logs under `metrics/output/captures/`. `python -m metrics.runner` replays the captures offline and produces throughput/latency, integrity, and statistical-detectability results plus comparison charts.

## Results (17 captured runs)

| | ARP channel | MTNS channel |
|---|---|---|
| Avg time per transmission | 282.7 s | 274.5 s |
| Avg throughput | 4.74 bps | 0.29 bps |
| Overhead ratio | — | 2.34x |
| Message success rate | 100% (1–15 byte messages) | 100% (1–15 byte messages) |

- **Integrity**: 100% corruption-detection rate across all tests; threshold reconstruction (≥4 shares) always succeeds, sub-threshold reconstruction always correctly fails.
- **Statistical detectability**: the ARP channel is readily distinguishable from background traffic by standard statistical tests (chi-square, Kolmogorov–Smirnov, entropy, runs test) — the covert MACs don't look like normal ARP traffic. The MTNS channel passes most of the same tests (byte-level chi-square, entropy, serial correlation, runs test) but fails the inter-packet timing test, since the brute-force search for a hash match introduces a non-uniform delay between packets.

Full numbers are in `metrics/output/results/summary_report.txt` and the CSVs alongside it; charts are in `metrics/output/charts/`.

## Built with

Python, [Scapy](https://scapy.net/) (raw packet crafting and sniffing), pytest, pandas (metrics analysis).
