"""Record by record, what changed in the DNS of your domains since the last run.

    python dns_changes.py quanticdata.io quantumproxies.io --snapshot dns_snapshot.json

Looks up the records of each domain (A, AAAA, MX, TXT and NS by default, or
--types), compares them with the snapshot of the previous run, prints every
record added or removed and saves the new snapshot. The first run only saves it.
"""

import argparse
import json
import os

from quanticdata_whois_api import WhoisLookup

TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "SRV", "PTR", "DS", "DNSKEY", "HTTPS"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("domains", nargs="+")
    parser.add_argument("--types", nargs="*", choices=TYPES, help="record types (default A AAAA MX TXT NS)")
    parser.add_argument("--snapshot", default="dns_snapshot.json")
    args = parser.parse_args()

    previous = {}
    if os.path.exists(args.snapshot):
        with open(args.snapshot, encoding="utf-8") as fh:
            previous = json.load(fh)

    lookup = WhoisLookup()
    current = {}
    for domain in args.domains:
        records = lookup.dns(domain, types=args.types or None, max_results=100)
        current[domain] = sorted({f"{r['type']} {r['value']}" for r in records})
        if domain not in previous:
            print(f"{domain}: {len(current[domain])} records saved")
            continue
        before, now = set(previous[domain]), set(current[domain])
        for line in sorted(now - before):
            print(f"{domain}: + {line}")
        for line in sorted(before - now):
            print(f"{domain}: - {line}")
        if before == now:
            print(f"{domain}: no change")

    with open(args.snapshot, "w", encoding="utf-8") as fh:
        json.dump({**previous, **current}, fh, indent=1)


if __name__ == "__main__":
    main()
