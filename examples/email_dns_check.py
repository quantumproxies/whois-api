"""MX hosts and SPF record of a list of domains, side by side.

    python email_dns_check.py quanticdata.io quantumproxies.io --out email_dns.csv

One row per domain with its mail servers (by priority) and its SPF record,
and a line for each domain that publishes neither.
"""

import argparse

from quanticdata_whois_api import WhoisLookup, write


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("domains", nargs="+")
    parser.add_argument("--out", default="email_dns.csv")
    args = parser.parse_args()

    lookup = WhoisLookup()
    rows = []
    for domain in args.domains:
        records = lookup.dns(domain, types=["MX", "TXT"], max_results=100)
        mx = sorted((r for r in records if r["type"] == "MX"), key=lambda r: r.get("priority") or 0)
        spf = [r["value"].strip('"') for r in records if r["type"] == "TXT" and "v=spf1" in r["value"]]
        rows.append({
            "domain": domain,
            "mx_hosts": "; ".join(r.get("target") or r["value"] for r in mx),
            "spf": " | ".join(spf),
        })
        if not mx and not spf:
            print(f"{domain}: no MX and no SPF record")
        else:
            print(f"{domain}: {len(mx)} MX, {'SPF' if spf else 'no SPF'}")

    write(rows, args.out)
    print(f"{len(rows)} domains written to {args.out}")


if __name__ == "__main__":
    main()
