"""Errors raised by the client. Every one carries a message a person can act on."""

from __future__ import annotations

from typing import Any, Optional


class QuanticDataError(Exception):
    """Base class for every error this package raises."""


class AuthError(QuanticDataError):
    """Not signed in, or the saved login can no longer be refreshed."""


class APIError(QuanticDataError):
    """The API answered with an error status."""

    def __init__(self, status: int, message: str, *, code: Optional[str] = None,
                 body: Any = None, request_id: Optional[str] = None) -> None:
        self.status = status
        self.code = code
        self.body = body
        self.request_id = request_id
        suffix = f" (request {request_id})" if request_id else ""
        super().__init__(f"HTTP {status}: {message}{suffix}")


class InsufficientCredit(APIError):
    """HTTP 402: the account has no credit left for this call."""


class RateLimited(APIError):
    """HTTP 429 after every retry: slow down or raise the plan's rate limit."""

    def __init__(self, *args: Any, retry_after: Optional[float] = None, **kwargs: Any) -> None:
        self.retry_after = retry_after
        super().__init__(*args, **kwargs)


class InvalidInput(APIError):
    """HTTP 400/422: a parameter is missing or out of range."""


class JobFailed(QuanticDataError):
    """An asynchronous run ended in a failed state."""

    def __init__(self, run_id: str, status: str, message: str = "") -> None:
        self.run_id = run_id
        self.status = status
        super().__init__(f"run {run_id} ended with status {status}" + (f": {message}" if message else ""))


class JobTimeout(QuanticDataError):
    """An asynchronous run did not finish within the wait limit."""

    def __init__(self, run_id: str, waited: float) -> None:
        self.run_id = run_id
        self.waited = waited
        super().__init__(f"run {run_id} still running after {waited:.0f}s; fetch it later with its id")
