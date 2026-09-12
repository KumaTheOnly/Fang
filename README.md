# Fang

Fang is a recon/orchestration tool that chains together nmap, httpx, feroxbuster, subfinder, nuclei, whatweb, and ffuf into a single automated pipeline — built for offensive security work and bug bounty recon.

Made by Yahya Taha Kazzi

## What it does

Fang runs a dependency-aware pipeline against a target:

- nmap and subfinder run first, concurrently (neither depends on the other)
- httpx runs once nmap finishes, confirming which discovered ports are actually live HTTP/S services
- feroxbuster, nuclei, whatweb, and ffuf all run concurrently once httpx finishes, since they only depend on httpx's confirmed live URLs
- sqlmap is available but opt-in only (--sqlmap), since it's invasive and shouldn't fire automatically

## Requirements

- Python 3.10+
- nmap, httpx, feroxbuster, subfinder, nuclei, whatweb, ffuf, sqlmap installed and on your PATH
- SecLists for default wordlists (sudo apt install seclists)

Tested on Linux (native and WSL).

## Installation

```bash
git clone https://github.com/KumaTheOnly/Fang.git
cd Fang
pip install -r requirements.txt
```

## Usage

```bash
python3 fang.py scan example.com
python3 fang.py scan example.com --ports 1-65535 --threads 100 --severity high,critical
python3 fang.py scan example.com --sqlmap
```

### Options

| Flag | Description | Default |
|---|---|---|
| --ports | nmap port range | 1-1000 |
| --wordlist | Override feroxbuster wordlist path | SecLists raft-medium-directories.txt |
| --threads | feroxbuster/ffuf thread count | 50 |
| --severity | nuclei severity filter | low,medium,high,critical |
| --sqlmap | Also run sqlmap against the first live URL | off |
| --sqlmap-url | Specific URL for sqlmap to test (implies --sqlmap) | none |
| --output | Path to write the JSON report | output/<target>_report.json |

## Output

Fang writes a full JSON report to output/<target>_report.json containing every module's findings, status, and duration.

## Legal / Responsible Use

Fang is built for authorized security testing only — your own infrastructure, or targets explicitly in scope for a bug bounty program or a penetration test you're contracted for.

Do not run Fang, or any of the tools it wraps, against systems you don't have explicit permission to test. Unauthorized scanning may be illegal in your jurisdiction. You are solely responsible for how you use this tool.

## License

MIT — see LICENSE.
