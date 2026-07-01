# Port Scanner

A lightweight, multi-threaded TCP port scanner written in Python using raw sockets — no external dependencies.

## Features
- Multi-threaded scanning for fast results across large port ranges
- TCP connect scanning via Python's `socket` module
- Maps common ports to well-known services (HTTP, SSH, FTP, MySQL, etc.)
- Configurable port range and thread count via CLI arguments
- Hostname resolution with clean error handling

## Usage
```bash
python3 port_scanner.py <target> [--start 1] [--end 1024] [--threads 100]
```

### Example
```bash
python3 port_scanner.py scanme.nmap.org --start 1 --end 1024
```

## How it works
1. Resolves the target hostname to an IP address
2. Loads the requested port range into a thread-safe queue
3. Spins up a pool of worker threads, each pulling ports off the queue and attempting a TCP connection (`connect_ex`)
4. Ports that accept a connection are recorded as open and reported with their common service name

## Notes
Only scan hosts you own or have explicit permission to test (e.g. `scanme.nmap.org`, which Nmap provides for public testing).
