"""Domains of a portfolio that expire soon.

    python expiry_watch.py --domains domains.txt --days 60

Reads domains from domains.txt (one per line), looks up their registration
data and prints the ones that expire within --days, soonest first, with the
registrar and status codes. All of them go to domain_expiry.csv with the
days left. Needs a login (`whois-api login`) or QUANTICDATA_API_KEY.
"""

import argparse
from datetime import datetime, timezone
from typing import Optional

from quanticdata_whois_api import WhoisLookup, write


def parse_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--domains", default="domains.txt", help="file with one domain per line")
    parser.add_argument("--days", type=int, default=60, help="report domains expiring within this many days")
    parser.add_argument("--out", default="domain_expiry.csv")
    args = parser.parse_args()

    with open(args.domains, encoding="utf-8") as fh:
        domains = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

    lookup = WhoisLookup()
    now = datetime.now(timezone.utc)
    rows = []
    # One whois run takes up to 25 domains.
    for i in range(0, len(domains), 25):
        batch = domains[i:i + 25]
        for d in lookup.whois(batch, max_results=len(batch)):
            expires = parse_time(d.get("expires"))
            rows.append({"days_left": (expires - now).days if expires else None, **d})

    rows.sort(key=lambda r: r["days_left"] if r["days_left"] is not None else 10 ** 6)
    for r in rows:
        if r["days_left"] is not None and r["days_left"] <= args.days:
            print(f"{r['days_left']:5} days  {r['domain']:30} {r.get('registrar') or ''}  {', '.join(r.get('status') or [])}")
    write(rows, args.out)
    print(f"{len(rows)} domains written to {args.out}")


if __name__ == "__main__":
    main()
