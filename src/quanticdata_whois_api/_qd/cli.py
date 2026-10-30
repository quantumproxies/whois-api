"""Command line built from the package's spec.json.

Every collector command gets its arguments from the collector's own input
schema (names, types, enums, ranges, defaults), so the help text and the
validation are the API's, not a hand-written copy that drifts.

    <tool> login                 sign in with the browser (OAuth)
    <tool> login --api-key       paste an API key instead
    <tool> whoami                which login is in use
    <tool> <command> ...         run a collector, print a table or write -o file
    <tool> run <run_id>          fetch a run started with --no-wait
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from . import auth, output
from .client import Client
from .errors import APIError, AuthError, InsufficientCredit, InvalidInput, JobTimeout, QuanticDataError, RateLimited


def _read_list(values: Sequence[str]) -> List[str]:
    """Accept ``a b c``, ``a,b,c``, ``@file.txt`` (one per line) and ``-`` (stdin)."""
    items: List[str] = []
    for v in values:
        if v == "-":
            items.extend(line.strip() for line in sys.stdin)
        elif v.startswith("@") and os.path.isfile(v[1:]):
            with open(v[1:], encoding="utf-8") as fh:
                items.extend(line.strip() for line in fh)
        elif "," in v and "://" not in v:
            items.extend(part.strip() for part in v.split(","))
        else:
            items.append(v.strip())
    return [i for i in items if i and not i.startswith("#")]


def _flag(name: str) -> str:
    return "--" + name.rstrip("_").replace("_", "-")


def _add_input(p: argparse.ArgumentParser, field: Dict[str, Any], positional: bool) -> None:
    name, kind = field.get("arg") or field["name"], field["type"]
    help_text = field.get("description", "")
    if field.get("default") is not None and kind != "boolean" and "default" not in help_text.lower():
        help_text += f" Default: {field['default']}."
    kw: Dict[str, Any] = {"help": help_text}
    if field.get("enum"):
        kw["choices"] = field["enum"]
    optional_positional = positional and not field.get("required")
    if kind.endswith("[]"):
        kw["nargs"] = ("*" if optional_positional else "+") if positional else "*"
        kw["metavar"] = name.upper().rstrip("S") if positional else "VALUE"
    elif optional_positional:
        kw["nargs"] = "?"
    elif kind == "integer":
        kw["type"] = int
    elif kind == "number":
        kw["type"] = float
    if field.get("tool_default"):
        kw["default"] = field["default"]
    if kind == "boolean":
        p.add_argument(_flag(name), dest=name, action=argparse.BooleanOptionalAction,
                       default=field["default"] if field.get("tool_default") else None, help=help_text)
        return
    if positional:
        p.add_argument(name, **kw)
    else:
        kw["dest"] = name
        if field.get("required") and not field.get("tool_default"):
            kw["required"] = True  # the API would refuse the call without it
        p.add_argument(_flag(name), **kw)


def _collect_input(args: argparse.Namespace, command: Dict[str, Any]) -> Dict[str, Any]:
    data: Dict[str, Any] = {}
    for field in command["inputs"]:
        name = field["name"]
        value = getattr(args, field.get("arg") or name, None)
        if value is None or value == []:
            continue
        if field["type"].endswith("[]"):
            value = _read_list(value if isinstance(value, list) else [value])
            if field["type"] in ("integer[]", "number[]"):
                cast = int if field["type"] == "integer[]" else float
                value = [cast(v) for v in value]
        if field["type"] == "integer" and (field.get("min") is not None and value < field["min"]
                                           or field.get("max") is not None and value > field["max"]):
            raise SystemExit(f"error: {_flag(name)} must be between {field.get('min')} and {field.get('max')}")
        data[name] = value
    return data


def build_parser(spec: Dict[str, Any]) -> argparse.ArgumentParser:
    prog = spec["cli"]
    parser = argparse.ArgumentParser(prog=prog, description=spec["description"],
                                     epilog=f"Docs and pricing: {spec['links']['page']}")
    parser.add_argument("--version", action="version", version=f"{prog} {spec['version']}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("login", help="sign in with your QuanticData account (opens the browser)")
    p.add_argument("--no-browser", action="store_true", help="print the sign-in link instead of opening a browser")
    p.add_argument("--api-key", nargs="?", const="", default=None, metavar="KEY",
                   help="save an API key instead of signing in (asks for it when KEY is omitted)")
    sub.add_parser("logout", help="revoke and forget the saved login")
    sub.add_parser("whoami", help="show which login this tool uses")
    p = sub.add_parser("run", help="fetch the rows of a run started with --no-wait")
    p.add_argument("run_id")
    _output_args(p)

    for command in spec["commands"]:
        p = sub.add_parser(command["name"], help=command["help"], description=command["description"])
        primary = command.get("positional")
        for field in command["inputs"]:
            _add_input(p, field, positional=(field["name"] == primary))
        _output_args(p, columns=command.get("columns"))
        if command.get("endpoint"):
            p.set_defaults(no_wait=False, timeout=1800)
        else:
            p.add_argument("--no-wait", action="store_true", help="start the run and print its id without waiting")
            p.add_argument("--timeout", type=float, default=900, help="seconds to wait for a run (default 900)")
        p.set_defaults(_command=command)
    return parser


def _output_args(p: argparse.ArgumentParser, columns: Optional[List[str]] = None) -> None:
    p.add_argument("-o", "--output", help="write to this file; the extension picks the format (.csv, .json, .jsonl)")
    p.add_argument("--format", choices=output.FORMATS, help="force a format (default: table on screen)")
    p.add_argument("--columns", help="comma-separated columns for the table view"
                   + (f" (default: {','.join(columns)})" if columns else ""))
    p.set_defaults(_columns=columns)


def _emit(rows: List[Dict[str, Any]], args: argparse.Namespace, meta: Dict[str, Any],
          full: Optional[Dict[str, Any]] = None) -> None:
    columns = args.columns.split(",") if args.columns else args._columns
    fmt = args.format or output.guess_format(args.output)
    key = (getattr(args, "_command", None) or {}).get("content_key")
    ext = os.path.splitext(args.output or "")[1].lower()
    if full is not None and key and ext in (".md", ".markdown", ".txt", ".html", ".htm"):
        # scrape -o page.md: the page itself, not its JSON envelope.
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(str(full.get(key) or ""))
        print(f"{len(str(full.get(key) or ''))} characters written to {args.output}", file=sys.stderr)
        return
    if full is not None and fmt == "json":
        # Layer calls (search, scrape, map): .json is the whole response, the
        # table/CSV/JSONL views are its main list.
        n = output.write_object(full, args.output)
    else:
        n = output.write(rows, args.output, args.format, columns=columns)
    if args.output and args.output != "-":
        cost = meta.get("cost_usd")
        extra = f", ${cost:.4f}" if isinstance(cost, (int, float)) else ""
        print(f"{n} rows written to {args.output}{extra}", file=sys.stderr)


def main(spec: Dict[str, Any], argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser(spec)
    args = parser.parse_args(argv)
    client = Client(user_agent=f"{spec['cli']}/{spec['version']} (+{spec['links']['repo']})")
    try:
        if args.command is None:
            parser.print_help()
            return 0
        if args.command == "login":
            if args.api_key is not None:
                key = args.api_key or getpass.getpass("API key (from the dashboard, API keys page): ")
                auth.save_api_key(client.oauth, key)
                print(f"API key saved in {auth.store.credentials_path()}", file=sys.stderr)
                return 0
            auth.login(client.oauth, open_browser=not args.no_browser)
            print("Signed in. Every QuanticData tool on this machine can now use this login.", file=sys.stderr)
            return 0
        if args.command == "logout":
            print("Signed out." if auth.logout(client.oauth) else "Nothing to sign out from.", file=sys.stderr)
            return 0
        if args.command == "whoami":
            kind = client.credentials.kind()
            print({"oauth": "Signed in with the browser (OAuth).",
                   "api_key": "Using an API key.",
                   "none": "Not signed in. Run: " + spec["cli"] + " login"}[kind])
            return 0 if kind != "none" else 1
        if args.command == "run":
            run = client.get_run(args.run_id)
            _emit(run.rows, args, run.meta)
            return 0
        command = args._command
        payload = _collect_input(args, command)
        if command.get("endpoint"):
            run = client.layer(command["endpoint"], {**command.get("fixed", {}), **payload},
                               rows_key=command.get("rows_key"), row_field=command.get("row_field", "value"),
                               timeout=args.timeout)
            _emit(run.rows, args, run.meta, full=run.meta)
            return 0
        run = client.run_collector(command["collector"], payload, wait=not args.no_wait, timeout=args.timeout)
        if args.no_wait and not run.done:
            print(run.run_id)
            print(f"Fetch it later with: {spec['cli']} run {run.run_id}", file=sys.stderr)
            return 0
        _emit(run.rows, args, run.meta)
        return 0
    except AuthError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except InsufficientCredit:
        print(f"error: no credit left on this account. Top up at {spec['links']['billing']}", file=sys.stderr)
        return 4
    except RateLimited as e:
        print(f"error: {e}. Wait a minute, or see plans with higher limits at {spec['links']['pricing']}", file=sys.stderr)
        return 5
    except InvalidInput as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except JobTimeout as e:
        print(f"error: {e}", file=sys.stderr)
        return 6
    except QuanticDataError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3 if isinstance(e, APIError) and e.status == 401 else 1
    except KeyboardInterrupt:
        return 130


def load_spec(package_dir: str) -> Dict[str, Any]:
    with open(os.path.join(package_dir, "spec.json"), encoding="utf-8") as fh:
        return json.load(fh)
