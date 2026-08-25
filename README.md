# WHOIS / RDAP domain lookup API — examples

Domain registration data over RDAP — registrar, dates, status, nameservers.

**Live page, full schema & pricing → [quanticdata.io/collectors/whois-api/](https://quanticdata.io/collectors/whois-api/)**

Looks up domain registration data over RDAP, the structured successor to WHOIS, resolving each TLD's authoritative registry through rdap.org. One row per domain: registrar (with IANA id), creation/expiry/last-update dates, EPP status codes, nameservers and DNSSEC delegation. Domains that don't resolve are reported under failed and never billed. No rate-limited WHOIS ports, no key.

## Quick start (curl)

```bash
curl -X POST https://api.quanticdata.io/v1/scraper/collectors/whois_domain/run \
  -H "Authorization: Bearer $QD_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domains": ["google.com"], "max_results": 1}'
```

## Python

See [`example.py`](example.py):

```bash
export QD_API_KEY=qd_live_...   # https://quanticdata.io/
python3 example.py
```

## Inputs

- `domains` (array, required) — Bare domains or URLs.
- `max_results` (integer) — How many domains to deliver at most (1–25). You pay only for delivered domains.

## Output — one row per domain

| field | type | description |
|---|---|---|
| `rank` | integer | 1-based position. |
| `domain` | string | Domain. |
| `registrar` | string | Registrar name. |
| `registrar_iana_id` | string | IANA registrar id. |
| `created` | string | Registration date. |
| `expires` | string | Expiration date. |
| `updated` | string | Last change. |
| `status` | string[] | EPP status codes. |
| `nameservers` | string[] | Delegated nameservers. |
| `dnssec` | boolean | DNSSEC delegation signed. |
| `url` | string | RDAP record URL. |

## Pricing

**$0.0005 per delivered domain** ($0.5 per 1,000). A run that delivers nothing costs nothing, and failed rows are never billed. The $2/month free allowance covers roughly 4,000 domains — no card required.

## Links

- This collector: https://quanticdata.io/collectors/whois-api/
- All collectors: https://quanticdata.io/collectors/
- Docs: https://quanticdata.io/docs/
