# Port Scanner (Python)

A fast, lightweight TCP port scanner with optional banner grabbing

## Features
- Scan port ranges (e.g., `1-1024`) and lists (e.g., `22,80,443`)
- Concurrency for speed (`--concurrency`)
- Adjustable timeout
- Optional banner grabbing (`--banner`)
- Zero dependencies (pure Python stdlib)

## Usage
```bash
chmod +x scanner.py
./scanner.py scanme.nmap.org                 # default 1–1024
./scanner.py 192.168.1.10 -p 22,80,443
./scanner.py example.com -p 1-65535 -t 0.3 -c 500 -b
