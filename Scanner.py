#Author: Raisa Methila
#A lightweight Python TCP port scanner that checks specified ports on a target host using concurrent connections.
#Supports customizable port ranges, timeouts, optional banner grabbing, and DNS skipping for fast, educational network scanning.

import argparse
import socket
import concurrent.futures
from datetime import datetime

def check_port(host: str, port: int, timeout: float, banner: bool):
    """Try connecting to host:port; return dict with status (+ optional banner)."""
    result = {
        "port": port,
        "open": False,
        "service": None,
        "banner": None
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((host, port)) == 0:
                result["open"] = True
                # Best-effort service name
                try:
                    result["service"] = socket.getservbyport(port)
                except Exception:
                    result["service"] = "unknown"
                if banner:
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        data = s.recv(256)
                        if data:
                            result["banner"] = data.decode(errors="ignore").strip()
                    except Exception:
                        pass
    except Exception:
        pass
    return result

def parse_ports(ports_str: str):
    """
    Parse "20-25,53,80,443" -> sorted list of ints.
    """
    ports = set()
    for chunk in ports_str.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            a, b = chunk.split("-", 1)
            a, b = int(a), int(b)
            for p in range(min(a, b), max(a, b) + 1):
                ports.add(p)
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 1 <= p <= 65535)

def resolve_host(target: str) -> str:
    # Returns IP for display consistency
    try:
        return socket.gethostbyname(target)
    except Exception:
        return target

def main():
    parser = argparse.ArgumentParser(
        description="Lightweight TCP port scanner (education-only)."
    )
    parser.add_argument("target", help="Target hostname or IP (e.g., scanme.nmap.org)")
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help='Ports to scan, e.g. "1-1024" or "22,80,443" or "20-25,53,80,443". Default: 1-1024'
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float, default=0.5,
        help="Socket timeout in seconds (default: 0.5)"
    )
    parser.add_argument(
        "-c", "--concurrency",
        type=int, default=200,
        help="Number of concurrent connections (default: 200)"
    )
    parser.add_argument(
        "-b", "--banner",
        action="store_true",
        help="Attempt simple banner grabbing on open ports"
    )
    parser.add_argument(
        "--no-dns",
        action="store_true",
        help="Skip DNS resolution (useful if scanning IPs directly)"
    )
    args = parser.parse_args()

    target = args.target
    host_ip = target if args.no_dns else resolve_host(target)
    ports = parse_ports(args.ports)

    print(f"\n[+] Target: {target} ({host_ip})")
    print(f"[+] Ports: {args.ports}")
    print(f"[+] Timeout: {args.timeout}s | Concurrency: {args.concurrency} | Banner: {args.banner}")
    print(f"[+] Started: {datetime.utcnow().isoformat()}Z\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futs = [executor.submit(check_port, host_ip, p, args.timeout, args.banner) for p in ports]
        for fut in concurrent.futures.as_completed(futs):
            results.append(fut.result())

    open_results = [r for r in results if r["open"]]
    if not open_results:
        print("No open ports found in the specified range.")
        return

    # Sort by port number
    open_results.sort(key=lambda r: r["port"])

    print("PORT    STATE  SERVICE    BANNER")
    print("-----   -----  ---------  -----------------------------------------------")
    for r in open_results:
        port = str(r["port"]).ljust(7)
        state = "open".ljust(6)
        service = (r["service"] or "unknown").ljust(9)
        banner = (r["banner"] or "")
        if len(banner) > 60:
            banner = banner[:57] + "..."
        print(f"{port}{state} {service}  {banner}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
