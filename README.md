# WHOIS API

[![ci](https://github.com/quantumproxies/whois-api/actions/workflows/ci.yml/badge.svg)](https://github.com/quantumproxies/whois-api/actions/workflows/ci.yml) ![python](https://img.shields.io/badge/python-3.9%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green) ![dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)

Look up domains from Python or the command line: WHOIS registration data for a list of domains (registrar, creation, expiry and last-change dates, EPP status codes, nameservers, DNSSEC) and the DNS records of a domain (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA and more), one row each, as JSON or CSV. The code is free and open source (MIT). It runs on the QuanticData Data API: RDAP where the registry offers it, the registry's WHOIS server where it does not, with the same parsed fields either way. Sign in once and run a command.

```bash
pip install git+https://github.com/quantumproxies/whois-api
whois-api login
whois-api whois quanticdata.io quantumproxies.io -o domains.csv
```

`login` opens the QuanticData sign-in page in your browser. New accounts get $2 of free usage every month, no card required: [create one](https://app.quanticdata.io/register?utm_source=github&utm_medium=readme&utm_campaign=whois-api).

## What it scrapes

| Command | Input | Returns | Per run |
|---|---|---|---|
| `whois-api whois` | domains or URLs | Registrar, created, expires, updated, status, nameservers, DNSSEC, 11 fields per row ([fields and price](https://quanticdata.io/collectors/whois-api/?utm_source=github&utm_medium=readme&utm_campaign=whois-api)) | up to 25 |
| `whois-api dns` | domain, optional --types | Type, TTL, value, priority, target host, 8 fields per row ([fields and price](https://quanticdata.io/collectors/dns-lookup-api/?utm_source=github&utm_medium=readme&utm_campaign=whois-api)) | up to 100 |

`dns` looks up A, AAAA, MX, TXT and NS by default; `--types` picks others, one or more of CNAME, SOA, CAA, SRV, PTR, DS, DNSKEY and HTTPS (`--types MX TXT`).

## Sample output

A real row from `whois-api whois quanticdata.io quantumproxies.io --max-results 2` (2026-10-23):

```json
{
  "url": "whois://whois.nic.io/quanticdata.io",
  "rank": 1,
  "dnssec": false,
  "domain": "quanticdata.io",
  "status": [
    "clientDeleteProhibited",
    "clientRenewProhibited",
    "clientTransferProhibited",
    "clientUpdateProhibited"
  ],
  "created": "2026-07-25T23:19:22.000Z",
  "expires": "2027-07-25T23:19:22.000Z",
  "updated": "2026-08-11T19:00:02.000Z",
  "registrar": "GoDaddy.com, LLC",
  "nameservers": [
    "lara.ns.cloudflare.com",
    "jakub.ns.cloudflare.com"
  ],
  "registrar_iana_id": "146"
}
```

## Python

```python
from quanticdata_whois_api import WhoisLookup

lookup = WhoisLookup()  # saved login, or QUANTICDATA_API_KEY

domains = lookup.whois(["quanticdata.io", "quantumproxies.io"])
for d in domains:
    print(d["domain"], d["registrar"], d["created"], d["expires"], d["nameservers"])
domains.to_csv("domains.csv")

records = lookup.dns("quanticdata.io", types=["MX", "TXT", "NS"])
for r in records:
    print(r["type"], r["ttl"], r["priority"], r["value"])
```

Each call returns a `Run`: iterate it for the rows (plain dicts), take `len()`, or save it with `to_csv()`, `to_json()`, `to_jsonl()` or `to_dataframe()` (pandas). Errors are specific: `InsufficientCredit`, `RateLimited`, `InvalidInput`, `JobFailed`, `AuthError`.

## Examples

- **Domain expiry watch**: Check a portfolio of domains and list the ones that expire within the next days, with registrar and status codes, soonest first. See [`examples/expiry_watch.py`](examples/expiry_watch.py).
- **Email DNS check**: For a list of domains, read the MX hosts and the SPF record in one pass and write them side by side in a CSV, with the domains that have neither. See [`examples/email_dns_check.py`](examples/email_dns_check.py).
- **DNS change log**: Save the records of your domains to a snapshot and print every record added or removed since the previous run. See [`examples/dns_changes.py`](examples/dns_changes.py).

## Command line

Results print as a table; `-o file.csv`, `-o file.json` or `-o file.jsonl` writes a file. List inputs take `a b c`, `a,b,c`, `@file.txt` (one per line) or `-` (stdin). `--no-wait` starts a long run in the background and prints its id; `whois-api run <id> -o out.csv` collects it later.

### `whois-api whois`

Registration data of each domain from its registry: registrar and its IANA id, creation, expiry and last-change dates, EPP status codes, nameservers and DNSSEC. RDAP is used where the TLD offers it, the registry's WHOIS server otherwise.

```
whois-api whois DOMAINS [options]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `DOMAINS` | string[] |  | Bare domains or URLs, e.g. quanticdata.io. |
| `--max-results` | integer | `10` | How many domains to deliver at most (1–25). Set it to the number of domains you send when that is more than 10. You pay only for delivered domains. |

### `whois-api dns`

DNS records of a domain, resolved over DNS over HTTPS, one row per record: type, TTL, data, MX and SRV priority and the host the record points to.

```
whois-api dns DOMAIN [options]
```

| Option | Type | Default | Description |
|---|---|---|---|
| `DOMAIN` | string |  | Domain to resolve, e.g. quanticdata.io. |
| `--types` | A / AAAA / MX / TXT / NS / CNAME / SOA / CAA / SRV / PTR / DS / DNSKEY / HTTPS |  | Record types to look up (default A, AAAA, MX, TXT, NS). |
| `--max-results` | integer | `50` | How many records to deliver at most (1–100). You pay only for delivered records. |

## Output fields

<details><summary><code>whois-api whois</code>: 11 fields</summary>

| Field | Type | Description |
|---|---|---|
| `rank` | integer | 1-based position. |
| `domain` | string | Domain. |
| `registrar` | string or null | Registrar name. |
| `registrar_iana_id` | string or null | IANA registrar id. |
| `created` | string or null | Registration date. |
| `expires` | string or null | Expiration date. |
| `updated` | string or null | Last change. |
| `status` | string[] | EPP status codes (clientTransferProhibited...). |
| `nameservers` | string[] | Delegated nameservers. |
| `dnssec` | boolean or null | DNSSEC delegation signed. |
| `url` | string | RDAP record URL, or a whois:// address (server and domain) when the registry's WHOIS server answered. |

</details>

<details><summary><code>whois-api dns</code>: 8 fields</summary>

| Field | Type | Description |
|---|---|---|
| `rank` | integer | 1-based position. |
| `domain` | string | Record owner name. |
| `type` | string | Record type. |
| `ttl` | integer or null | TTL seconds. |
| `value` | string | Record data. |
| `priority` | integer or null | MX/SRV priority. |
| `target` | string or null | Host the record points to (MX, SRV, NS, CNAME, PTR). |
| `dnssec_validated` | boolean or null | Whether the resolver validated the answer with DNSSEC. |

</details>

## Sign-in and API keys

- `whois-api login` signs you in with OAuth 2.1 and PKCE in the browser. The token is stored in `~/.config/quanticdata/credentials.json` (readable only by you) and refreshed automatically. One login serves every QuanticData tool on the machine.
- No browser on the machine (SSH, Docker, Colab): run `whois-api login --no-browser`, open the link anywhere, then paste back the address the browser ends on.
- Scripts and CI: set `QUANTICDATA_API_KEY` to a key from the dashboard, or store one with `whois-api login --api-key`.
- `whois-api logout` revokes the token. The connection is listed under API keys in the dashboard as "API · QuanticData CLI"; deleting that key disconnects every machine that uses it.

## Pricing

The code is free and MIT-licensed. Runs are billed to your QuanticData account per delivered row, at the price shown on each collector page linked above; $2 of usage is free every month and failed runs are never billed. Plans with higher limits: [pricing](https://quanticdata.io/pricing/?utm_source=github&utm_medium=readme&utm_campaign=whois-api).

## Other ways to call it

The same data over plain HTTP:

```bash
curl -X POST https://api.quanticdata.io/v1/scraper/collectors/whois_domain/run \
  -H "Authorization: Bearer $QUANTICDATA_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"input": {"domains": ["quanticdata.io", "quantumproxies.io"], "max_results": 2}}'
```

- [API reference](https://quanticdata.io/docs/?utm_source=github&utm_medium=readme&utm_campaign=whois-api) with Python, Node, PHP and curl examples.
- [MCP server](https://quanticdata.io/mcp-server/?utm_source=github&utm_medium=readme&utm_campaign=whois-api) to give Claude, Cursor or any MCP client the same tools.
- [n8n node](https://github.com/quantumproxies/n8n-nodes-quanticdata) for no-code workflows.

## FAQ

**Is this WHOIS API free?**

The code is free and MIT-licensed. Lookups run on your QuanticData account: $2 of usage is free every month with no card, then you pay per delivered row at the price shown on each collector page. Failed runs are never billed.

**Do I need a WHOIS API key or proxies?**

Only your QuanticData login: whois-api login in a terminal, or QUANTICDATA_API_KEY from the dashboard in scripts. There is no key to request from each registry, no WHOIS server list to maintain and no proxy to configure; the lookups run on QuanticData's side.

**Does it use RDAP or WHOIS?**

Both. RDAP, the JSON successor of WHOIS, is used where the registry offers it; for a TLD without RDAP the registry's WHOIS server answers. The row has the same fields either way, and its url says which one was read.

**How many domains can one run return?**

Up to 25 domains per whois run and 100 DNS records per dns lookup; set --max-results and you pay only for what is delivered.

**Can I export to CSV or JSON?**

Add -o domains.csv (or .json, .jsonl). Status codes and nameservers are joined with '; ', so the file opens cleanly in Excel or Google Sheets.

**Can I run it on a schedule?**

Yes. Set QUANTICDATA_API_KEY in the environment and call the CLI, examples/expiry_watch.py or examples/dns_changes.py from cron, GitHub Actions or any scheduler.

## Related scrapers

- [Subdomain Finder](https://github.com/quantumproxies/subdomain-finder): Subdomain finder for Python and the command line.
- [Wayback Machine Scraper](https://github.com/quantumproxies/wayback-machine-scraper): Wayback Machine scraper for Python and the command line.
- [Web Scraper API](https://github.com/quantumproxies/web-scraper-api): Web scraper API for Python and the command line.

## License

MIT. Built and maintained by [QuanticData](https://quanticdata.io/?utm_source=github&utm_medium=readme&utm_campaign=whois-api).
