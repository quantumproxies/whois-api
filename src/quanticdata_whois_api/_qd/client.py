"""HTTP client for the QuanticData Data API (https://api.quanticdata.io/v1).

Standard library only. What it takes care of so the calling code does not:

- auth: the saved browser login (refreshed when it expires, and once more on a
  401) or an API key from ``QUANTICDATA_API_KEY``;
- retries: 429 honours ``Retry-After``; 502/503/504 and dropped connections
  back off exponentially with jitter. Collector runs are safe to resend: the
  API returns the existing run for an identical input inside its dedup window;
- long jobs: a collector run that goes to the background is polled until it
  finishes, with a growing interval and an overall deadline;
- errors: one exception per situation (no credit, rate limited, bad input,
  failed at the source), each with the API's own message.
"""

from __future__ import annotations

import json
import os
import random
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional

from . import auth, output
from .errors import (APIError, AuthError, InsufficientCredit, InvalidInput, JobFailed, JobTimeout,
                     RateLimited)

# Overridable for local development and tests; the defaults are production.
API_BASE = os.environ.get("QUANTICDATA_API_BASE", "https://api.quanticdata.io/v1")
ISSUER = os.environ.get("QUANTICDATA_ISSUER", "https://app.quanticdata.io")
RESOURCE = os.environ.get("QUANTICDATA_RESOURCE", "https://api.quanticdata.io/v1")
OAUTH_SCOPE = "mcp"
CLIENT_NAME = "QuanticData CLI"

RETRY_STATUS = {429, 502, 503, 504}
FINAL_STATES = {"done", "failed", "cancelled", "canceled", "error"}


@dataclass
class Run:
    """One collector run: its rows plus what the API says about it."""

    run_id: str
    status: str
    rows: List[Dict[str, Any]] = field(default_factory=list)
    count: int = 0
    partial: bool = False
    cost_usd: Optional[float] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def done(self) -> bool:
        return self.status == "done"

    def __iter__(self) -> Iterator[Dict[str, Any]]:
        return iter(self.rows)

    def __len__(self) -> int:
        return len(self.rows)

    def to_csv(self, path: str) -> int:
        """Write the rows to a CSV file (nested fields flattened) and return how many."""
        return output.write(self.rows, path, "csv")

    def to_json(self, path: str) -> int:
        return output.write(self.rows, path, "json")

    def to_jsonl(self, path: str) -> int:
        return output.write(self.rows, path, "jsonl")

    def to_dataframe(self) -> Any:
        """The rows as a pandas DataFrame (needs ``pip install pandas``)."""
        try:
            import pandas as pd  # type: ignore[import-not-found]
        except ImportError as e:  # pragma: no cover - optional dependency
            raise ImportError("to_dataframe() needs pandas: pip install pandas") from e
        return pd.json_normalize(self.rows)

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "Run":
        cost = payload.get("cost") or {}
        usage = payload.get("usage") or {}
        rows = payload.get("results") or []
        cost_usd = cost.get("usd") if isinstance(cost, dict) else None
        if cost_usd is None and isinstance(usage, dict):
            cost_usd = usage.get("cost_usd")
        meta = {k: v for k, v in payload.items() if k != "results"}
        meta["cost_usd"] = cost_usd
        return cls(run_id=str(payload.get("run_id", "")), status=str(payload.get("status", "")),
                   rows=list(rows), count=int(payload.get("count") or len(rows)),
                   partial=bool(payload.get("partial")), cost_usd=cost_usd, meta=meta)


class Client:
    """Thin, careful wrapper around the REST API.

    >>> qd = Client()                       # saved login or QUANTICDATA_API_KEY
    >>> run = qd.run_collector("amazon_search", {"query": "usb c hub", "max_results": 20})
    >>> run.rows[0]["asin"]
    """

    def __init__(self, api_key: Optional[str] = None, *, base_url: Optional[str] = None,
                 user_agent: str = "quanticdata-oss", timeout: float = 180.0, max_retries: int = 4) -> None:
        self.base_url = (base_url or os.environ.get("QUANTICDATA_API_BASE") or API_BASE).rstrip("/")
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_retries = max_retries
        self.oauth = auth.OAuthConfig(issuer=os.environ.get("QUANTICDATA_ISSUER") or ISSUER,
                                      resource=os.environ.get("QUANTICDATA_RESOURCE") or RESOURCE, scope=OAUTH_SCOPE,
                                      client_name=CLIENT_NAME, user_agent=user_agent)
        self.credentials = auth.Credentials(self.oauth, api_key=api_key)

    # -- transport ---------------------------------------------------------

    def request(self, method: str, path: str, *, body: Optional[Dict[str, Any]] = None,
                params: Optional[Dict[str, Any]] = None, raw: bool = False) -> Any:
        """Send one call and return the envelope's ``payload`` (or the raw body text)."""
        url = self.base_url + path
        if params:
            url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}, doseq=True)
        data = json.dumps(body).encode("utf-8") if body is not None else None
        refreshed = False
        attempt = 0
        while True:
            headers = {"Accept": "text/csv" if raw else "application/json", "User-Agent": self.user_agent}
            headers.update(self.credentials.headers())
            if data is not None:
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    text = resp.read().decode("utf-8")
                    return text if raw else _payload(text)
            except urllib.error.HTTPError as e:
                status = e.code
                text = e.read().decode("utf-8", "replace")
                if status == 401 and not refreshed and self.credentials.kind() == "oauth":
                    # The access token died early (revoked, clock skew): refresh once and resend.
                    refreshed = True
                    self.credentials.headers(force_refresh=True)
                    continue
                if status in RETRY_STATUS and attempt < self.max_retries:
                    time.sleep(_backoff(attempt, e.headers.get("Retry-After")))
                    attempt += 1
                    continue
                raise _error(status, text, e.headers) from None
            except (urllib.error.URLError, socket.timeout, ConnectionError) as e:
                if attempt < self.max_retries:
                    time.sleep(_backoff(attempt, None))
                    attempt += 1
                    continue
                reason = getattr(e, "reason", e)
                raise APIError(0, f"cannot reach {urllib.parse.urlsplit(url).netloc}: {reason}") from None

    # -- collectors ----------------------------------------------------------

    def collectors(self, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """The live collector catalog: slug, input/output schema, price, health."""
        payload = self.request("GET", "/scraper/collectors", params={"category": category})
        return list(payload.get("collectors", [])) if isinstance(payload, dict) else []

    def collector(self, slug: str) -> Dict[str, Any]:
        return self.request("GET", f"/scraper/collectors/{urllib.parse.quote(slug)}")

    def run_collector(self, slug: str, input: Dict[str, Any], *, wait: bool = True,
                      timeout: float = 900.0, force_async: bool = False) -> Run:
        """Run a collector. Short runs come back with their rows; long ones are polled."""
        body: Dict[str, Any] = {"input": {k: v for k, v in input.items() if v is not None}}
        if force_async or not wait:
            body["async"] = True
        payload = self.request("POST", f"/scraper/collectors/{urllib.parse.quote(slug)}/run", body=body)
        run = Run.from_payload(payload)
        if run.status == "failed":
            raise JobFailed(run.run_id, run.status, str(payload.get("error") or ""))
        if run.status in FINAL_STATES or not wait:
            return run
        return self.wait_run(run.run_id, timeout=timeout)

    def get_run(self, run_id: str) -> Run:
        return Run.from_payload(self.request("GET", f"/scraper/collectors/runs/{urllib.parse.quote(run_id)}"))

    def get_run_csv(self, run_id: str) -> str:
        return self.request("GET", f"/scraper/collectors/runs/{urllib.parse.quote(run_id)}",
                            params={"format": "csv"}, raw=True)

    def wait_run(self, run_id: str, *, timeout: float = 900.0) -> Run:
        started = time.monotonic()
        interval = 1.5
        while True:
            run = self.get_run(run_id)
            if run.status in FINAL_STATES:
                if run.status != "done":
                    raise JobFailed(run_id, run.status, str(run.meta.get("error") or ""))
                return run
            waited = time.monotonic() - started
            if waited > timeout:
                raise JobTimeout(run_id, waited)
            time.sleep(min(interval, max(0.5, timeout - waited)))
            interval = min(interval * 1.5, 10.0)

    # -- other layers of the Data API ----------------------------------------

    LAYER_PATHS = {"serp": "/serp", "scrape": "/scrape", "map": "/map", "unlock": "/scraper/unlock"}

    def layer(self, endpoint: str, body: Dict[str, Any], *, rows_key: Optional[str] = None,
              row_field: str = "value", timeout: float = 1800.0) -> Run:
        """Call one layer endpoint and return it as a Run: ``meta`` is the whole
        response, ``rows`` the list under ``rows_key`` (or the response itself)."""
        body = {k: v for k, v in body.items() if v is not None}
        if endpoint == "crawl":
            payload = self.crawl(body.pop("url"), timeout=timeout, **body)
            rows_key = rows_key or "pages"
        else:
            payload = self.request("POST", self.LAYER_PATHS[endpoint], body=body)
        found = dig(payload, rows_key) if rows_key else None
        rows = found if isinstance(found, list) else ([] if rows_key else [payload])
        rows = [r if isinstance(r, dict) else {row_field: r} for r in rows]
        meta = payload if isinstance(payload, dict) else {"value": payload}
        run_id = str((meta.get("search_metadata") or {}).get("id") or meta.get("id") or "")
        return Run(run_id=run_id, status="done", rows=rows, count=len(rows), meta=meta)

    def scrape(self, url: str, **options: Any) -> Dict[str, Any]:
        """One page as Markdown, HTML, text or structured JSON (POST /scrape)."""
        return self.request("POST", "/scrape", body={"url": url, **options})

    def serp(self, query: str, **options: Any) -> Dict[str, Any]:
        """Search results as JSON: Google, Bing or DuckDuckGo, any vertical (POST /serp)."""
        return self.request("POST", "/serp", body={"query": query, **options})

    def map(self, url: str, **options: Any) -> Dict[str, Any]:
        """Every URL a site exposes, from sitemaps and links, without a crawl (POST /map)."""
        return self.request("POST", "/map", body={"url": url, **options})

    def crawl(self, url: str, *, wait: bool = True, timeout: float = 1800.0, **options: Any) -> Dict[str, Any]:
        """Crawl a site to Markdown (POST /crawl), polling the job until it finishes."""
        job = self.request("POST", "/crawl", body={"url": url, **options})
        job_id = job.get("id") or job.get("jobId")
        if not wait or not job_id:
            return job
        pages: List[Dict[str, Any]] = []
        since: Optional[int] = None
        started = time.monotonic()
        interval = 2.0
        while True:
            status = self.request("GET", f"/crawl/{urllib.parse.quote(str(job_id))}",
                                  params={"since": since, "include_content": "true"})
            pages.extend(status.get("pages") or [])
            since = status.get("nextCursor", since)
            if status.get("status") in FINAL_STATES or status.get("status") == "completed":
                status["pages"] = pages
                return status
            if time.monotonic() - started > timeout:
                raise JobTimeout(str(job_id), time.monotonic() - started)
            time.sleep(interval)
            interval = min(interval * 1.5, 15.0)

    def unlock(self, url: str, **options: Any) -> Dict[str, Any]:
        """The raw HTTP response of a URL from a residential IP (POST /scraper/unlock)."""
        return self.request("POST", "/scraper/unlock", body={"url": url, **options})


def dig(data: Any, path: Optional[str]) -> Any:
    """``dig(resp, "trends.interest_over_time")``: follow a dotted path, None when it breaks."""
    for part in (path or "").split("."):
        if not part:
            continue
        if not isinstance(data, dict):
            return None
        data = data.get(part)
    return data


def _payload(text: str) -> Any:
    if not text:
        return {}
    data = json.loads(text)
    if isinstance(data, dict) and "payload" in data and data.get("type") in ("response", "error", None):
        return data["payload"] if data["payload"] is not None else {}
    return data


def _backoff(attempt: int, retry_after: Optional[str]) -> float:
    if retry_after:
        try:
            return min(float(retry_after), 120.0)
        except ValueError:
            pass
    return min(60.0, (2 ** attempt) * 1.0) * (0.5 + random.random())


def _error(status: int, text: str, headers: Any) -> APIError:
    try:
        data = json.loads(text) if text else {}
    except ValueError:
        data = {"message": text[:300]}
    if not isinstance(data, dict):
        data = {"message": str(data)[:300]}
    payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
    message = str(data.get("message") or data.get("error") or payload.get("error") or "request failed")
    request_id = headers.get("X-Request-Id") if headers else None
    kwargs = {"code": payload.get("code"), "body": data, "request_id": request_id}
    if status == 402:
        return InsufficientCredit(status, message, **kwargs)
    if status == 429:
        retry = headers.get("Retry-After") if headers else None
        return RateLimited(status, message, retry_after=float(retry) if retry and retry.isdigit() else None, **kwargs)
    if status in (400, 404, 422):
        return InvalidInput(status, message, **kwargs)
    if status == 401:
        return APIError(status, message + " (run the `login` command again, or check QUANTICDATA_API_KEY)", **kwargs)
    if status == 424:
        return APIError(status, message + " (failed at the source, not billed: safe to retry)", **kwargs)
    return APIError(status, message, **kwargs)


__all__ = ["Client", "Run", "API_BASE", "AuthError"]
