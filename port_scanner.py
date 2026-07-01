#!/usr/bin/env python3
"""
Simple Port Scanner
--------------------
A lightweight, multi-threaded TCP port scanner built with Python sockets.
Scans a target host over a given port range and reports open ports along
with the common service name associated with each (when known).

Usage:
    python3 port_scanner.py <target> [--start 1] [--end 1024] [--threads 100]

Example:
    python3 port_scanner.py scanme.nmap.org --start 1 --end 1024
"""

import argparse
import socket
import sys
import threading
import queue
import time
from datetime import datetime


# A small lookup of common ports -> service names (like a mini Nmap "well-known ports" table)
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-Proxy",
}


def scan_port(target: str, port: int, timeout: float = 0.5) -> bool:
    """Attempt a TCP connection to a single port. Returns True if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            return result == 0
    except socket.error:
        return False


def worker(target: str, port_queue: "queue.Queue[int]", open_ports: list, lock: threading.Lock):
    """Thread worker: pulls ports off the queue and scans them."""
    while True:
        try:
            port = port_queue.get_nowait()
        except queue.Empty:
            return

        if scan_port(target, port):
            with lock:
                open_ports.append(port)

        port_queue.task_done()


def resolve_target(target: str) -> str:
    """Resolve a hostname to an IP address, exit cleanly if it fails."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"[!] Could not resolve host: {target}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Simple multi-threaded TCP port scanner")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("--start", type=int, default=1, help="Start port (default: 1)")
    parser.add_argument("--end", type=int, default=1024, help="End port (default: 1024)")
    parser.add_argument("--threads", type=int, default=100, help="Number of worker threads (default: 100)")
    args = parser.parse_args()

    ip = resolve_target(args.target)

    print("-" * 50)
    print(f"Scanning target: {args.target} ({ip})")
    print(f"Port range:      {args.start}-{args.end}")
    print(f"Started at:      {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 50)

    port_queue: "queue.Queue[int]" = queue.Queue()
    for port in range(args.start, args.end + 1):
        port_queue.put(port)

    open_ports = []
    lock = threading.Lock()
    threads = []

    start_time = time.time()

    for _ in range(min(args.threads, args.end - args.start + 1)):
        t = threading.Thread(target=worker, args=(ip, port_queue, open_ports, lock))
        t.daemon = True
        t.start()
        threads.append(t)

    port_queue.join()

    elapsed = time.time() - start_time
    open_ports.sort()

    print(f"\nScan completed in {elapsed:.2f} seconds\n")

    if open_ports:
        print(f"{'PORT':<10}{'STATE':<10}{'SERVICE'}")
        for port in open_ports:
            service = COMMON_PORTS.get(port, "unknown")
            print(f"{port:<10}{'open':<10}{service}")
    else:
        print("No open ports found in the given range.")


if __name__ == "__main__":
    main()
