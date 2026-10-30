"""Row types of each command, for editors and type checkers (rows are plain dicts)."""

from typing import Any, Dict, List, Optional

try:  # Python 3.8+
    from typing import TypedDict
except ImportError:  # pragma: no cover
    from typing_extensions import TypedDict  # type: ignore


class WhoisDomainRow(TypedDict, total=False):
    """One row of `whois-api whois` (whois_domain v1.3.1)."""

    rank: int
    """1-based position."""
    domain: str
    """Domain."""
    registrar: Optional[str]
    """Registrar name."""
    registrar_iana_id: Optional[str]
    """IANA registrar id."""
    created: Optional[str]
    """Registration date."""
    expires: Optional[str]
    """Expiration date."""
    updated: Optional[str]
    """Last change."""
    status: List[str]
    """EPP status codes (clientTransferProhibited...)."""
    nameservers: List[str]
    """Delegated nameservers."""
    dnssec: Optional[bool]
    """DNSSEC delegation signed."""
    url: str
    """RDAP record URL, or a whois:// address (server and domain) when the registry's WHOIS server answered."""

class DnsRecordsRow(TypedDict, total=False):
    """One row of `whois-api dns` (dns_records v1.1.0)."""

    rank: int
    """1-based position."""
    domain: str
    """Record owner name."""
    type: str
    """Record type."""
    ttl: Optional[int]
    """TTL seconds."""
    value: str
    """Record data."""
    priority: Optional[int]
    """MX/SRV priority."""
    target: Optional[str]
    """Host the record points to (MX, SRV, NS, CNAME, PTR)."""
    dnssec_validated: Optional[bool]
    """Whether the resolver validated the answer with DNSSEC."""
