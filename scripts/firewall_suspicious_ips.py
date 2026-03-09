#!/usr/bin/env python3
"""Parse firewall logs and extract suspicious source IP addresses.

Supported patterns include:
- key/value logs such as: "SRC=1.2.3.4 DST=5.6.7.8 ACTION=DROP"
- syslog-ish variants with lower-case keys: "src=1.2.3.4 action=deny"
- generic IPv4 detection as fallback when deny/drop/reject appears in the line

Suspicious logic:
1) Any line containing a blocked action (drop/deny/reject/blocked) marks the source IP as suspicious.
2) Any source IP that appears at least --threshold times in the log is marked suspicious.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
from collections import Counter
from pathlib import Path

ACTION_RE = re.compile(r"\b(?:ACTION|action)=(?P<action>[A-Za-z_]+)\b")
SRC_RE = re.compile(r"\b(?:SRC|src|source|SOURCE)=(?P<src>\d{1,3}(?:\.\d{1,3}){3})\b")
IP_RE = re.compile(r"\b(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")
BLOCKED_ACTIONS = {"drop", "deny", "denied", "reject", "blocked"}


def valid_ipv4(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


def parse_log(path: Path, threshold: int) -> list[str]:
    counts: Counter[str] = Counter()
    blocked_ips: set[str] = set()

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            src_match = SRC_RE.search(line)
            action_match = ACTION_RE.search(line)

            src_ip = src_match.group("src") if src_match else None
            if src_ip and valid_ipv4(src_ip):
                counts[src_ip] += 1

            action = action_match.group("action").lower() if action_match else ""
            if src_ip and action in BLOCKED_ACTIONS:
                blocked_ips.add(src_ip)
            elif action in BLOCKED_ACTIONS:
                for m in IP_RE.finditer(line):
                    ip = m.group("ip")
                    if valid_ipv4(ip):
                        blocked_ips.add(ip)

    suspicious = set(blocked_ips)
    suspicious.update(ip for ip, count in counts.items() if count >= threshold)
    return sorted(suspicious, key=lambda ip: tuple(int(p) for p in ip.split(".")))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Extract suspicious IPs from firewall logs")
    parser.add_argument("logfile", type=Path, help="Path to firewall log file")
    parser.add_argument(
        "-t",
        "--threshold",
        type=int,
        default=10,
        help="Flag IPs seen at least this many times (default: 10)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be >= 1")

    if not args.logfile.exists():
        parser.error(f"Log file not found: {args.logfile}")

    for ip in parse_log(args.logfile, args.threshold):
        print(ip)


if __name__ == "__main__":
    main()
