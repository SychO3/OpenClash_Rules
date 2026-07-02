#!/usr/bin/env python3
"""Aggregate CIDR list into a Clash classical rule-provider yaml.

Reads a file where each line is "TYPE,cidr" (TYPE = IP-CIDR or IP-CIDR6),
collapses overlapping/redundant subnets, and prints a `payload:` block.

Usage: aggregate_cidr.py <input_file>
"""
import ipaddress
import sys

nets = []
with open(sys.argv[1]) as f:
    for line in f:
        parts = line.strip().split(",")
        if len(parts) >= 2:
            try:
                nets.append(ipaddress.ip_network(parts[1], strict=False))
            except ValueError:
                pass

collapsed_v4 = ipaddress.collapse_addresses(sorted(n for n in nets if n.version == 4))
collapsed_v6 = ipaddress.collapse_addresses(sorted(n for n in nets if n.version == 6))

print("payload:")
for n in collapsed_v4:
    print(f"  - IP-CIDR,{n},no-resolve")
for n in collapsed_v6:
    print(f"  - IP-CIDR6,{n},no-resolve")
