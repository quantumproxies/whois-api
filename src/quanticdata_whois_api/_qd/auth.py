"""Sign in with a QuanticData account: OAuth 2.1 authorization code + PKCE.

The flow a person sees: ``<tool> login`` opens the browser on the QuanticData
consent page, they sign in (or create an account) and approve, the browser
lands on a one-shot listener on 127.0.0.1 and the terminal says "Signed in".
No key to copy. On a machine without a browser (SSH, Docker, Colab) the same
command prints the link; open it anywhere and paste back the address the
browser ends up on.

What it does, per the specs it follows:
- RFC 8414 discovery of the authorization server's endpoints;
- RFC 7636 PKCE with S256 (the only method the server accepts);
- RFC 8252 native-app loopback redirect on 127.0.0.1, any free port;
- RFC 9207 ``iss`` check on the redirect, plus a random ``state``;
- RFC 7591 dynamic registration, or a Client ID Metadata Document when the
  tool ships one (the consent page then shows a verified name);
- RFC 8707 ``resource`` so the token is bound to the Data API;
- refresh tokens rotate; refreshes are serialised across processes (store.py).

An API key (``QUANTICDATA_API_KEY`` or ``login --api-key``) skips all of this.
"""

from __future__ import annotations

import base64
import hashlib
import html
import http.server
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from typing import Any, Callable, Dict, Optional, Tuple

from . import store
from .errors import AuthError

ENV_API_KEY = "QUANTICDATA_API_KEY"
REFRESH_MARGIN_S = 60


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def pkce_pair() -> Tuple[str, str]:
    """Return ``(verifier, challenge)`` for PKCE S256."""
    verifier = _b64url(secrets.token_bytes(48))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class OAuthConfig:
    """Everything the flow needs to know about one deployment."""

    def __init__(self, *, issuer: str, resource: str, scope: str, client_name: str,
                 client_id_metadata_url: Optional[str] = None,
                 user_agent: str = "quanticdata-oss") -> None:
        self.issuer = issuer.rstrip("/")
        self.resource = resource
        self.scope = scope
        self.client_name = client_name
        self.client_id_metadata_url = client_id_metadata_url
        self.user_agent = user_agent


def _http_json(method: str, url: str, user_agent: str, *, form: Optional[Dict[str, str]] = None,
               body: Optional[Dict[str, Any]] = None, timeout: float = 30.0) -> Tuple[int, Dict[str, Any]]:
    headers = {"Accept": "application/json", "User-Agent": user_agent}
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        raw = e.read()
        status = e.code
    except urllib.error.URLError as e:
        raise AuthError(f"cannot reach {urllib.parse.urlsplit(url).netloc}: {e.reason}") from e
    try:
        parsed = json.loads(raw.decode("utf-8") or "{}")
    except ValueError:
        parsed = {"error": "invalid_response", "error_description": raw[:200].decode("utf-8", "replace")}
    return status, parsed if isinstance(parsed, dict) else {"value": parsed}


def discover(cfg: OAuthConfig) -> Dict[str, Any]:
    url = f"{cfg.issuer}/.well-known/oauth-authorization-server"
    status, meta = _http_json("GET", url, cfg.user_agent)
    if status != 200 or "authorization_endpoint" not in meta or "token_endpoint" not in meta:
        raise AuthError(f"no OAuth metadata at {url} (HTTP {status})")
    if meta.get("issuer", cfg.issuer).rstrip("/") != cfg.issuer:
        raise AuthError(f"issuer mismatch: expected {cfg.issuer}, metadata says {meta.get('issuer')}")
    if "S256" not in meta.get("code_challenge_methods_supported", ["S256"]):
        raise AuthError("the server does not support PKCE S256")
    return meta


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    result: Dict[str, str] = {}
    done = threading.Event()

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return
        params = dict(urllib.parse.parse_qsl(parsed.query))
        type(self).result.update(params)
        ok = "code" in params and "error" not in params
        title = "Signed in" if ok else "Sign-in failed"
        detail = ("You can close this tab and go back to the terminal." if ok
                  else html.escape(params.get("error_description") or params.get("error") or "unknown error"))
        page = (f"<!doctype html><meta charset=utf-8><title>{title}</title>"
                f"<body style=\"font:16px system-ui;margin:15vh auto;max-width:28rem;text-align:center\">"
                f"<h1 style=\"font-size:22px\">{title}</h1><p>{detail}</p></body>")
        body = page.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)
        type(self).done.set()

    def log_message(self, *_: Any) -> None:  # keep the terminal clean
        return


def _bind_loopback() -> Tuple[http.server.HTTPServer, int]:
    """Listen on a free port of 127.0.0.1. The server matches loopback redirects
    on host and path only (RFC 8252 §7.3), so any port the OS hands out works."""
    try:
        server = http.server.HTTPServer(("127.0.0.1", 0), _CallbackHandler)
    except OSError as e:
        raise AuthError(f"cannot open a local port for the sign-in callback: {e}") from e
    return server, server.server_address[1]


REDIRECT_URI = "http://127.0.0.1/callback"


def _redirect_uris(cfg: OAuthConfig) -> list:
    return [REDIRECT_URI]


def _client_id(cfg: OAuthConfig, meta: Dict[str, Any]) -> str:
    if cfg.client_id_metadata_url and meta.get("client_id_metadata_document_supported"):
        return cfg.client_id_metadata_url
    saved = (store.get_profile(cfg.issuer) or {}).get("client")
    if isinstance(saved, dict) and saved.get("client_id") and saved.get("redirect_uris") == _redirect_uris(cfg):
        return saved["client_id"]
    reg = meta.get("registration_endpoint")
    if not reg:
        raise AuthError("the server offers neither a client metadata document nor dynamic registration")
    status, client = _http_json("POST", reg, cfg.user_agent, body={
        "client_name": cfg.client_name,
        "redirect_uris": _redirect_uris(cfg),
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "scope": cfg.scope,
    })
    if status not in (200, 201) or not client.get("client_id"):
        raise AuthError(f"client registration failed (HTTP {status}): {client.get('error_description') or client}")
    profile = store.get_profile(cfg.issuer) or {}
    profile["client"] = {"client_id": client["client_id"], "redirect_uris": _redirect_uris(cfg)}
    store.put_profile(cfg.issuer, profile)
    return client["client_id"]


def _parse_pasted(text: str) -> Dict[str, str]:
    text = text.strip()
    query = urllib.parse.urlsplit(text).query if "://" in text else text.lstrip("?")
    return dict(urllib.parse.parse_qsl(query))


def login(cfg: OAuthConfig, *, open_browser: bool = True, timeout: float = 300.0,
          echo: Callable[[str], None] = lambda s: print(s, file=sys.stderr),
          read_line: Callable[[], str] = lambda: sys.stdin.readline()) -> Dict[str, Any]:
    """Run the browser sign-in and save the tokens. Returns the saved profile."""
    meta = discover(cfg)
    client_id = _client_id(cfg, meta)
    server, port = _bind_loopback()
    _CallbackHandler.result = {}
    _CallbackHandler.done = threading.Event()
    verifier, challenge = pkce_pair()
    state = _b64url(secrets.token_bytes(24))
    redirect_uri = f"http://127.0.0.1:{port}/callback"
    url = meta["authorization_endpoint"] + "?" + urllib.parse.urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": cfg.scope,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "resource": cfg.resource,
    })

    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
    thread.start()
    pasted: Dict[str, str] = {}

    def wait_for_paste() -> None:
        line = read_line()
        if line.strip():
            pasted.update(_parse_pasted(line))
            _CallbackHandler.done.set()

    try:
        opened = open_browser and _try_open(url)
        echo("Opening the QuanticData sign-in page in your browser." if opened
             else "Open this link in a browser to sign in:")
        echo(f"\n  {url}\n")
        echo("Waiting for the browser... If it ends on a page that does not load "
             "(another machine, SSH), paste that page's full address here and press Enter.")
        threading.Thread(target=wait_for_paste, daemon=True).start()
        if not _CallbackHandler.done.wait(timeout):
            raise AuthError(f"no answer from the browser within {int(timeout)}s; run login again")
    finally:
        server.shutdown()
        server.server_close()

    params = pasted or dict(_CallbackHandler.result)
    if params.get("error"):
        raise AuthError(f"sign-in refused: {params.get('error_description') or params['error']}")
    if not secrets.compare_digest(params.get("state", ""), state):
        raise AuthError("the sign-in answer does not match this login (state mismatch); run login again")
    if meta.get("authorization_response_iss_parameter_supported") and params.get("iss") \
            and params["iss"].rstrip("/") != cfg.issuer:
        raise AuthError(f"the sign-in answer comes from {params['iss']}, not {cfg.issuer}")
    if not params.get("code"):
        raise AuthError("the browser came back without an authorization code")

    status, tok = _http_json("POST", meta["token_endpoint"], cfg.user_agent, form={
        "grant_type": "authorization_code",
        "code": params["code"],
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier,
        "resource": cfg.resource,
    })
    if status != 200 or not tok.get("access_token"):
        raise AuthError(f"token exchange failed (HTTP {status}): {tok.get('error_description') or tok.get('error') or tok}")
    with store.locked():
        profile = store.get_profile(cfg.issuer) or {}
        profile.update(_token_fields(tok))
        profile["client_id"] = client_id
        profile["token_endpoint"] = meta["token_endpoint"]
        profile["revocation_endpoint"] = meta.get("revocation_endpoint")
        profile.pop("api_key", None)
        store.put_profile(cfg.issuer, profile)
    return profile


def _try_open(url: str) -> bool:
    if os.environ.get("QUANTICDATA_NO_BROWSER") or (sys.platform.startswith("linux") and
                                                      not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))):
        return False
    try:
        return webbrowser.open(url, new=1, autoraise=True)
    except webbrowser.Error:
        return False


def _token_fields(tok: Dict[str, Any]) -> Dict[str, Any]:
    out = {
        "access_token": tok["access_token"],
        "token_type": tok.get("token_type", "Bearer"),
        "expires_at": time.time() + float(tok.get("expires_in") or 3600),
        "scope": tok.get("scope"),
    }
    if tok.get("refresh_token"):
        out["refresh_token"] = tok["refresh_token"]
    return out


def save_api_key(cfg: OAuthConfig, api_key: str) -> None:
    with store.locked():
        store.put_profile(cfg.issuer, {"api_key": api_key.strip()})


def logout(cfg: OAuthConfig) -> bool:
    """Revoke the refresh token (best effort) and forget the login."""
    profile = store.get_profile(cfg.issuer)
    if not profile:
        return False
    token = profile.get("refresh_token") or profile.get("access_token")
    if token and profile.get("revocation_endpoint") and profile.get("client_id"):
        try:
            _http_json("POST", profile["revocation_endpoint"], cfg.user_agent,
                       form={"token": token, "client_id": profile["client_id"]}, timeout=10)
        except AuthError:
            pass
    with store.locked():
        store.put_profile(cfg.issuer, None)
    return True


class Credentials:
    """Hands out a valid ``Authorization`` header, refreshing when needed."""

    def __init__(self, cfg: OAuthConfig, api_key: Optional[str] = None) -> None:
        self.cfg = cfg
        self._explicit_key = api_key

    def kind(self) -> str:
        if self._explicit_key or os.environ.get(ENV_API_KEY):
            return "api_key"
        profile = store.get_profile(self.cfg.issuer) or {}
        if profile.get("api_key"):
            return "api_key"
        return "oauth" if profile.get("access_token") else "none"

    def headers(self, force_refresh: bool = False) -> Dict[str, str]:
        key = self._explicit_key or os.environ.get(ENV_API_KEY)
        if key:
            return {"Authorization": f"Bearer {key.strip()}"}
        profile = store.get_profile(self.cfg.issuer) or {}
        if profile.get("api_key"):
            return {"Authorization": f"Bearer {profile['api_key']}"}
        if not profile.get("access_token"):
            raise AuthError("not signed in: run the `login` command, or set QUANTICDATA_API_KEY")
        if force_refresh or float(profile.get("expires_at", 0)) - REFRESH_MARGIN_S < time.time():
            profile = self._refresh(seen_access_token=profile["access_token"])
        return {"Authorization": f"Bearer {profile['access_token']}"}

    def _refresh(self, seen_access_token: str) -> Dict[str, Any]:
        with store.locked():
            profile = store.get_profile(self.cfg.issuer) or {}
            # Another process refreshed while we waited for the lock: use its token.
            if profile.get("access_token") and profile["access_token"] != seen_access_token \
                    and float(profile.get("expires_at", 0)) - REFRESH_MARGIN_S > time.time():
                return profile
            if not profile.get("refresh_token"):
                raise AuthError("the saved login expired: run the `login` command again")
            status, tok = _http_json("POST", profile["token_endpoint"], self.cfg.user_agent, form={
                "grant_type": "refresh_token",
                "refresh_token": profile["refresh_token"],
                "client_id": profile["client_id"],
                "resource": self.cfg.resource,
            })
            if status != 200 or not tok.get("access_token"):
                if tok.get("error") in ("invalid_grant", "invalid_client", "unauthorized_client"):
                    store.put_profile(self.cfg.issuer, None)
                    raise AuthError("the saved login was revoked or expired: run the `login` command again")
                raise AuthError(f"token refresh failed (HTTP {status}): {tok.get('error_description') or tok}")
            profile.update(_token_fields(tok))
            store.put_profile(self.cfg.issuer, profile)
            return profile
