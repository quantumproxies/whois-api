"""WHOIS API: WHOIS API and DNS lookup API for Python and the command line: registrar, creation and expiry dates, status codes and nameservers of a list of domains, plus their A, AAAA, MX, TXT, NS and other DNS records, as JSON or CSV. Free and open source; one parsed format over RDAP and WHOIS, sign in with your QuanticData account.

    from quanticdata_whois_api import WhoisLookup

    scraper = WhoisLookup()   # saved login (`whois-api login`) or QUANTICDATA_API_KEY
    run = scraper.whois(...)   # WHOIS registration data for one or more domains
    run = scraper.dns(...)   # DNS records of a domain (A, AAAA, MX, TXT, NS and more)
"""

from typing import Any, Dict, Optional, Sequence, Union

from ._qd.client import Client, Run
from ._qd.errors import (APIError, AuthError, InsufficientCredit, InvalidInput, JobFailed, JobTimeout,
                         QuanticDataError, RateLimited)
from ._qd.output import write

__version__ = "0.1.0"
__all__ = ["WhoisLookup", "Run", "write", "APIError", "AuthError", "InsufficientCredit", "InvalidInput",
           "JobFailed", "JobTimeout", "QuanticDataError", "RateLimited", "__version__"]


def _as_list(value: Any) -> Any:
    if value is None or isinstance(value, (list, tuple)):
        return list(value) if value is not None else None
    return [value]


class WhoisLookup:
    """WHOIS API on the QuanticData Data API.

    Every method runs one collector and returns a :class:`Run`: iterate it for the
    rows (plain dicts, typed in ``types``), or save it with ``to_csv()``,
    ``to_json()``, ``to_jsonl()`` or ``to_dataframe()``.
    """

    def __init__(self, api_key: Optional[str] = None, *, timeout: float = 180.0) -> None:
        self.client = Client(api_key, user_agent="whois-api/0.1.0 (+https://github.com/quantumproxies/whois-api)", timeout=timeout)

    def whois(
        self, domains: Union[str, Sequence[str]],
        *,
        max_results: Optional[int] = None,
        wait: bool = True,
        timeout: float = 900.0,
    ) -> Run:
        """Registration data of each domain from its registry: registrar and its IANA id, creation, expiry and last-change dates, EPP status codes, nameservers and DNSSEC. RDAP is used where the TLD offers it, the registry's WHOIS server otherwise.

        Args:
            domains: Bare domains or URLs, e.g. quanticdata.io.
            max_results: How many domains to deliver at most (1–25). Set it to the number of domains you send when that is more than 10. You pay only for delivered domains.
            wait: False starts the run in the background and returns its id at once.
            timeout: seconds to wait for a background run before giving up.

        Returns up to 25 rows, one per domain: see ``types.WhoisDomainRow``.
        """
        payload = {
            "domains": _as_list(domains),
            "max_results": max_results,
        }
        return self.client.run_collector("whois_domain", payload, wait=wait, timeout=timeout)

    def dns(
        self, domain: str,
        *,
        types: Optional[Union[str, Sequence[str]]] = None,
        max_results: Optional[int] = None,
        wait: bool = True,
        timeout: float = 900.0,
    ) -> Run:
        """DNS records of a domain, resolved over DNS over HTTPS, one row per record: type, TTL, data, MX and SRV priority and the host the record points to.

        Args:
            domain: Domain to resolve, e.g. quanticdata.io.
            types: Record types to look up (default A, AAAA, MX, TXT, NS). One of: A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, SRV, PTR, DS, DNSKEY, HTTPS.
            max_results: How many records to deliver at most (1–100). You pay only for delivered records.
            wait: False starts the run in the background and returns its id at once.
            timeout: seconds to wait for a background run before giving up.

        Returns up to 100 rows, one per record: see ``types.DnsRecordsRow``.
        """
        payload = {
            "domain": domain,
            "types": _as_list(types),
            "max_results": max_results,
        }
        return self.client.run_collector("dns_records", payload, wait=wait, timeout=timeout)
