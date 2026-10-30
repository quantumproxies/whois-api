"""Offline tests: a fake QuanticData API and OAuth server on 127.0.0.1.

Covers the browser sign-in end to end (PKCE, state, iss, token exchange), the
headless paste-the-address variant, refresh-token rotation, one refresh shared
by concurrent callers, retries on 429, background runs, the error mapping and
every command of the CLI. No network, no account needed:

    python -m unittest discover -s tests -v
"""

import base64
import hashlib
import io
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
import urllib.request
from contextlib import redirect_stderr, redirect_stdout
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "src"))

import quanticdata_whois_api  # noqa: E402
from quanticdata_whois_api import WhoisLookup  # noqa: E402
from quanticdata_whois_api._qd import auth, cli, client as qd_client, store  # noqa: E402
from quanticdata_whois_api._qd.errors import AuthError, InsufficientCredit, InvalidInput  # noqa: E402

SPEC = cli.load_spec(os.path.dirname(quanticdata_whois_api.__file__))
FIXTURES = os.path.join(HERE, "fixtures")


def sample(slug):
    with open(os.path.join(FIXTURES, f"{slug}.json"), encoding="utf-8") as fh:
        return json.load(fh)


LAYER_PATHS = {"serp": "/v1/serp", "scrape": "/v1/scrape", "map": "/v1/map", "crawl": "/v1/crawl"}
COLLECTOR_COMMANDS = [c for c in SPEC["commands"] if not c.get("endpoint")]


def layer_response(path, body):
    """The sample of the command whose endpoint and fixed fields match this call."""
    for c in SPEC["commands"]:
        if c.get("endpoint") and LAYER_PATHS[c["endpoint"]] == path and \
                all(body.get(k) == v for k, v in (c.get("fixed") or {}).items()):
            return sample(c["sample"])["response"]
    return None


def expected_rows(command):
    if not command.get("endpoint"):
        return sample(command["sample"])["results"]
    resp = sample(command["sample"])["response"]
    rows = resp
    for part in (command.get("rows_key") or "").split("."):
        rows = rows.get(part) if part else rows
    rows = rows if command.get("rows_key") else [resp]
    return [r if isinstance(r, dict) else {command.get("row_field", "value"): r} for r in rows]


def call_path(command):
    return LAYER_PATHS[command["endpoint"]] if command.get("endpoint") else f"/v1/scraper/collectors/{command['collector']}/run"


class FakeServer:
    """API + authorization server in one, with switches for each scenario."""

    def __init__(self):
        self.lock = threading.Lock()
        self.reset()
        handler = self._handler()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def reset(self):
        self.calls = []
        self.fail_first = []          # statuses to answer, in order, before the real response
        self.async_runs = False
        self.polls_before_done = 1
        self.challenge = None
        self.access_tokens = set()
        self.refresh_tokens = set()
        self.refresh_calls = 0
        self.token_counter = 0

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _new_tokens(self):
        with self.lock:
            self.token_counter += 1
            n = self.token_counter
            at, rt = f"mcp_at_{n:064x}", f"mcp_rt_{n:064x}"
            self.access_tokens.add(at)
            self.refresh_tokens.add(rt)
        return {"access_token": at, "refresh_token": rt, "token_type": "Bearer", "expires_in": 3600, "scope": "mcp"}

    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                return

            def _send(self, status, body, headers=None):
                data = json.dumps(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(n).decode("utf-8") if n else ""
                if self.headers.get("Content-Type", "").startswith("application/x-www-form-urlencoded"):
                    return dict(urllib.parse.parse_qsl(raw))
                return json.loads(raw) if raw else {}

            def do_GET(self):
                path = urllib.parse.urlsplit(self.path).path
                server.calls.append(("GET", path, self.headers.get("Authorization")))
                if path == "/.well-known/oauth-authorization-server":
                    return self._send(200, {
                        "issuer": server.base,
                        "authorization_endpoint": f"{server.base}/oauth/authorize",
                        "token_endpoint": f"{server.base}/api/v1/oauth/token",
                        "registration_endpoint": f"{server.base}/api/v1/oauth/register",
                        "revocation_endpoint": f"{server.base}/api/v1/oauth/revoke",
                        "code_challenge_methods_supported": ["S256"],
                        "authorization_response_iss_parameter_supported": True,
                        "client_id_metadata_document_supported": True,
                    })
                if path.startswith("/v1/crawl/"):
                    c = next(c for c in SPEC["commands"] if c.get("endpoint") == "crawl")
                    resp = dict(sample(c["sample"])["response"], status="completed")
                    return self._send(200, {"type": "response", "payload": resp})
                if path.startswith("/v1/scraper/collectors/runs/"):
                    run_id = path.rsplit("/", 1)[1]
                    with server.lock:
                        server.polls_before_done -= 1
                        done = server.polls_before_done < 0
                    slug = run_id.split("--")[0]
                    if not done:
                        return self._send(200, {"type": "response", "payload": {"run_id": run_id, "status": "running"}})
                    command = next(c for c in SPEC["commands"] if c.get("collector") == slug)
                    payload = dict(sample(command["sample"]), run_id=run_id, status="done")
                    return self._send(200, {"type": "response", "payload": payload})
                return self._send(404, {"type": "error", "message": "not found"})

            def do_POST(self):
                path = urllib.parse.urlsplit(self.path).path
                body = self._body()
                auth_header = self.headers.get("Authorization")
                server.calls.append(("POST", path, auth_header, body))
                if path == "/api/v1/oauth/register":
                    assert body["token_endpoint_auth_method"] == "none"
                    assert body["redirect_uris"] == ["http://127.0.0.1/callback"]
                    return self._send(201, {"client_id": "mcp_client_test"})
                if path == "/api/v1/oauth/token":
                    if body.get("grant_type") == "authorization_code":
                        digest = hashlib.sha256(body["code_verifier"].encode()).digest()
                        expected = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
                        if body.get("code") != "code123" or expected != server.challenge:
                            return self._send(400, {"error": "invalid_grant"})
                        return self._send(200, server._new_tokens())
                    if body.get("grant_type") == "refresh_token":
                        with server.lock:
                            server.refresh_calls += 1
                            ok = body.get("refresh_token") in server.refresh_tokens
                            server.refresh_tokens.discard(body.get("refresh_token"))
                        time.sleep(0.05)  # widen the race window for the concurrency test
                        if not ok:
                            return self._send(400, {"error": "invalid_grant", "error_description": "Refresh token already used"})
                        return self._send(200, server._new_tokens())
                if path == "/api/v1/oauth/revoke":
                    return self._send(200, {})
                is_layer = path in LAYER_PATHS.values()
                if is_layer or (path.startswith("/v1/scraper/collectors/") and path.endswith("/run")):
                    slug = path.split("/")[-2]
                    if server.fail_first:
                        status = server.fail_first.pop(0)
                        headers = {"Retry-After": "0"} if status == 429 else {}
                        messages = {402: "Insufficient balance", 422: "Input can never resolve",
                                    401: "Invalid or expired OAuth access token", 429: "Slow down"}
                        return self._send(status, {"type": "error", "message": messages.get(status, "error")}, headers)
                    token = (auth_header or "").replace("Bearer ", "")
                    if token.startswith("mcp_at_") and token not in server.access_tokens:
                        return self._send(401, {"type": "error", "message": "Invalid or expired OAuth access token"})
                    if path == "/v1/crawl":
                        return self._send(200, {"type": "response", "payload": {"id": "crawl-1", "status": "running"}})
                    if is_layer:
                        resp = layer_response(path, body)
                        if resp is None:
                            return self._send(400, {"type": "error", "message": f"unexpected body {body}"})
                        return self._send(200, {"type": "response", "payload": resp})
                    if server.async_runs or body.get("async"):
                        return self._send(202, {"type": "response", "payload": {
                            "run_id": f"{slug}--1", "status": "queued", "statusUrl": f"/api/v1/scraper/collectors/runs/{slug}--1"}})
                    command = next(c for c in SPEC["commands"] if c.get("collector") == slug)
                    return self._send(200, {"type": "response", "payload": sample(command["sample"])})
                return self._send(404, {"type": "error", "message": "not found"})

        return Handler


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = FakeServer()

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def setUp(self):
        self.server.reset()
        self.tmp = tempfile.mkdtemp()
        self.env = {
            "QUANTICDATA_API_BASE": f"{self.server.base}/v1",
            "QUANTICDATA_ISSUER": self.server.base,
            "QUANTICDATA_RESOURCE": f"{self.server.base}/v1",
            "QUANTICDATA_CONFIG_DIR": os.path.join(self.tmp, "config"),
            "QUANTICDATA_NO_BROWSER": "1",
        }
        self._old_env = {k: os.environ.get(k) for k in list(self.env) + ["QUANTICDATA_API_KEY"]}
        os.environ.update(self.env)
        os.environ.pop("QUANTICDATA_API_KEY", None)
        self._sleep = qd_client.time.sleep
        qd_client.time.sleep = lambda s: None

    def tearDown(self):
        qd_client.time.sleep = self._sleep
        for k, v in self._old_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        shutil.rmtree(self.tmp, ignore_errors=True)

    def use_api_key(self):
        os.environ["QUANTICDATA_API_KEY"] = "qd_live_" + "0" * 64

    def oauth_cfg(self):
        return WhoisLookup().client.oauth

    def seed_login(self, expired=False):
        tokens = self.server._new_tokens()
        store.put_profile(self.server.base, {
            "access_token": tokens["access_token"], "refresh_token": tokens["refresh_token"],
            "expires_at": time.time() - 10 if expired else time.time() + 3600,
            "client_id": "mcp_client_test", "token_endpoint": f"{self.server.base}/api/v1/oauth/token",
            "revocation_endpoint": f"{self.server.base}/api/v1/oauth/revoke",
        })
        return tokens


def first_value(command):
    """A valid value for the command's main input, taken from the real sample run."""
    run = sample(command["sample"])
    value = run["input"][command["positional"]]
    return value if isinstance(value, list) else [value]


def py_call(scraper, command):
    """Call the command's method with the sample run's whole input."""
    given = sample(command["sample"])["input"]
    by_name = {i["name"]: i for i in command["inputs"]}
    value = first_value(command) if command["positional_is_list"] else first_value(command)[0]
    kwargs = {}
    for name, v in given.items():
        field = by_name.get(name)
        if name == command["positional"] or field is None or v is None:
            continue
        kwargs[field.get("arg") or name] = v
    return getattr(scraper, command["method"])(value, **kwargs)


def cli_args(command):
    """The sample run's whole input as command-line arguments (main input first)."""
    given = sample(command["sample"])["input"]
    args = [str(v) for v in first_value(command)]
    by_name = {i["name"]: i for i in command["inputs"]}
    for name, value in given.items():
        field = by_name.get(name)
        if name == command["positional"] or field is None or value is None:
            continue
        flag = "--" + (field.get("arg") or name).rstrip("_").replace("_", "-")
        if isinstance(value, bool):
            args.append(flag if value else "--no-" + flag[2:])
        elif isinstance(value, list):
            args += [flag] + [str(v) for v in value]
        else:
            args += [flag, str(value)]
    return args


class TestBrowserLogin(Base):
    def _browser(self, url):
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        self.assertEqual(q["code_challenge_method"], "S256")
        self.assertEqual(q["resource"], f"{self.server.base}/v1")
        self.server.challenge = q["code_challenge"]
        redirect = q["redirect_uri"] + "?" + urllib.parse.urlencode(
            {"code": "code123", "state": q["state"], "iss": self.server.base})
        threading.Thread(target=lambda: urllib.request.urlopen(redirect, timeout=10).read(), daemon=True).start()
        return True

    def test_login_saves_tokens_and_uses_them(self):
        original = auth._try_open
        auth._try_open = self._browser
        try:
            auth.login(self.oauth_cfg(), echo=lambda s: None, read_line=lambda: "")
        finally:
            auth._try_open = original
        profile = store.get_profile(self.server.base)
        self.assertTrue(profile["access_token"].startswith("mcp_at_"))
        self.assertEqual(profile["client_id"], "mcp_client_test")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(os.stat(store.credentials_path()).st_mode), 0o600)
        command = SPEC["commands"][0]
        run = py_call(WhoisLookup(), command)
        self.assertGreater(len(run), 0)
        self.assertEqual(self.server.calls[-1][2], f"Bearer {profile['access_token']}")

    def test_headless_login_by_pasting_the_address(self):
        printed = []
        url_ready = threading.Event()

        def echo(s):
            printed.append(s)
            if "oauth/authorize" in s:
                url_ready.set()

        def read_line():
            url_ready.wait(5)
            url = next(p.strip() for p in printed if "oauth/authorize" in p)
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
            self.server.challenge = q["code_challenge"]
            return "http://127.0.0.1:1/callback?" + urllib.parse.urlencode({"code": "code123", "state": q["state"]}) + "\n"

        auth.login(self.oauth_cfg(), open_browser=False, echo=echo, read_line=read_line)
        self.assertIn("access_token", store.get_profile(self.server.base))

    def test_state_mismatch_is_refused(self):
        printed = []
        url_ready = threading.Event()

        def echo(s):
            printed.append(s)
            if "oauth/authorize" in s:
                url_ready.set()

        def read_line():
            # Everything right (code, PKCE) except the state: only the state check can refuse it.
            url_ready.wait(5)
            url = next(p.strip() for p in printed if "oauth/authorize" in p)
            self.server.challenge = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))["code_challenge"]
            return "http://127.0.0.1:1/callback?code=code123&state=forged\n"

        with self.assertRaises(AuthError) as ctx:
            auth.login(self.oauth_cfg(), open_browser=False, echo=echo, read_line=read_line)
        self.assertIn("state", str(ctx.exception))
        self.assertFalse([c for c in self.server.calls if c[1] == "/api/v1/oauth/token"])


class TestTokens(Base):
    def test_expired_access_token_is_refreshed_and_rotated(self):
        old = self.seed_login(expired=True)
        command = SPEC["commands"][0]
        scraper = WhoisLookup()
        py_call(scraper, command)
        profile = store.get_profile(self.server.base)
        self.assertNotEqual(profile["refresh_token"], old["refresh_token"])
        self.assertEqual(self.server.refresh_calls, 1)
        self.assertEqual(self.server.calls[-1][2], f"Bearer {profile['access_token']}")

    def test_a_401_triggers_one_refresh_and_a_resend(self):
        self.seed_login()
        self.server.fail_first = [401]
        command = SPEC["commands"][0]
        run = py_call(WhoisLookup(), command)
        self.assertGreater(len(run), 0)
        self.assertEqual(self.server.refresh_calls, 1)

    def test_concurrent_callers_share_one_refresh(self):
        self.seed_login(expired=True)
        cfg = self.oauth_cfg()
        headers, errors = [], []

        def worker():
            try:
                headers.append(auth.Credentials(cfg).headers())
            except Exception as e:  # pragma: no cover - the assertion below reports it
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(self.server.refresh_calls, 1)
        self.assertEqual(len({h["Authorization"] for h in headers}), 1)

    def test_revoked_refresh_token_asks_for_a_new_login(self):
        tokens = self.seed_login(expired=True)
        self.server.refresh_tokens.discard(tokens["refresh_token"])
        with self.assertRaises(AuthError):
            auth.Credentials(self.oauth_cfg()).headers()
        self.assertIsNone(store.get_profile(self.server.base))

    def test_logout_forgets_the_login(self):
        self.seed_login()
        self.assertTrue(auth.logout(self.oauth_cfg()))
        self.assertIsNone(store.get_profile(self.server.base))


class TestRuns(Base):
    def setUp(self):
        super().setUp()
        self.use_api_key()

    def call(self, command):
        return py_call(WhoisLookup(), command)

    def test_every_command_returns_the_sample_rows(self):
        for command in SPEC["commands"]:
            with self.subTest(command=command["name"]):
                run = self.call(command)
                self.assertEqual(run.rows, expected_rows(command))
                post = [c for c in self.server.calls if c[0] == "POST"][-1]
                self.assertEqual(post[1], call_path(command))
                sent = post[3] if command.get("endpoint") else post[3]["input"]
                self.assertIn(command["positional"], sent)
                for k, v in (command.get("fixed") or {}).items():
                    self.assertEqual(sent[k], v)

    def test_rate_limit_is_retried(self):
        self.server.fail_first = [429, 429]
        run = self.call(SPEC["commands"][0])
        self.assertGreater(len(run), 0)
        self.assertEqual(len([c for c in self.server.calls if c[0] == "POST"]), 3)

    def test_background_runs_are_polled_until_done(self):
        if not COLLECTOR_COMMANDS:
            self.skipTest("no collector command in this tool")
        self.server.async_runs = True
        self.server.polls_before_done = 2
        run = self.call(COLLECTOR_COMMANDS[0])
        self.assertEqual(run.status, "done")
        self.assertEqual(len([c for c in self.server.calls if c[0] == "GET"]), 3)

    def test_errors_are_specific(self):
        self.server.fail_first = [402]
        with self.assertRaises(InsufficientCredit):
            self.call(SPEC["commands"][0])
        self.server.fail_first = [422]
        with self.assertRaises(InvalidInput):
            self.call(SPEC["commands"][0])

    def test_exports(self):
        run = self.call(SPEC["commands"][0])
        for ext in ("csv", "json", "jsonl"):
            path = os.path.join(self.tmp, f"out.{ext}")
            self.assertEqual(getattr(run, f"to_{ext}")(path), len(run))
            with open(path, encoding="utf-8") as fh:
                self.assertTrue(fh.read().strip())


class TestCli(Base):
    def setUp(self):
        super().setUp()
        self.use_api_key()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(SPEC, list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_every_command_writes_a_csv(self):
        for command in SPEC["commands"]:
            with self.subTest(command=command["name"]):
                path = os.path.join(self.tmp, f"{command['name']}.csv")
                code, _, err = self.run_cli(command["name"], *cli_args(command), "-o", path)
                self.assertEqual(code, 0, err)
                with open(path, encoding="utf-8") as fh:
                    header = fh.readline()
                self.assertIn(command["columns"][0], header)

    def test_table_on_screen(self):
        command = SPEC["commands"][0]
        code, out, _ = self.run_cli(command["name"], *cli_args(command))
        self.assertEqual(code, 0)
        self.assertIn(command["columns"][0], out.splitlines()[0])

    def test_json_output_of_a_layer_call_is_the_whole_response(self):
        command = next((c for c in SPEC["commands"] if c.get("endpoint") and c.get("rows_key")), None)
        if command is None:
            self.skipTest("no layer command in this tool")
        path = os.path.join(self.tmp, "full.json")
        code, _, err = self.run_cli(command["name"], *cli_args(command), "-o", path)
        self.assertEqual(code, 0, err)
        with open(path, encoding="utf-8") as fh:
            self.assertEqual(json.load(fh), sample(command["sample"])["response"])

    def test_list_input_from_file(self):
        command = next((c for c in SPEC["commands"] if c["positional_is_list"]), None)
        if command is None:
            self.skipTest("no list input in this tool")
        listing = os.path.join(self.tmp, "items.txt")
        with open(listing, "w", encoding="utf-8") as fh:
            fh.write("\n".join(first_value(command)) + "\n# a comment\n")
        code, _, err = self.run_cli(command["name"], f"@{listing}", "--format", "json")
        self.assertEqual(code, 0, err)
        sent = [c for c in self.server.calls if c[0] == "POST"][-1][3]["input"][command["positional"]]
        self.assertEqual(sent, first_value(command))

    def test_no_credit_exit_code(self):
        self.server.fail_first = [402]
        command = SPEC["commands"][0]
        code, _, err = self.run_cli(command["name"], *cli_args(command))
        self.assertEqual(code, 4)
        self.assertIn("Top up", err)

    def test_no_wait_prints_the_run_id(self):
        if not COLLECTOR_COMMANDS:
            self.skipTest("no collector command in this tool")
        command = COLLECTOR_COMMANDS[0]
        code, out, _ = self.run_cli(command["name"], *cli_args(command), "--no-wait")
        self.assertEqual(code, 0)
        self.assertEqual(out.strip(), f"{command['collector']}--1")
        code, out, _ = self.run_cli("run", f"{command['collector']}--1", "--format", "jsonl")
        self.assertEqual(code, 0)

    def test_help_and_version(self):
        with self.assertRaises(SystemExit) as ctx:
            self.run_cli("--version")
        self.assertEqual(ctx.exception.code, 0)
        code, out, _ = self.run_cli()
        self.assertEqual(code, 0)
        for command in SPEC["commands"]:
            self.assertIn(command["name"], out)

    def test_whoami_without_login(self):
        os.environ.pop("QUANTICDATA_API_KEY")
        code, out, _ = self.run_cli("whoami")
        self.assertEqual(code, 1)
        self.assertIn("login", out)


if __name__ == "__main__":
    unittest.main()
