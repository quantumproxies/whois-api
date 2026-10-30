"""Writers for result rows: JSON, JSON Lines, CSV and a plain terminal table.

Rows are plain dicts as the API returns them. CSV flattens nested objects with
dotted keys (``seller.name``) and joins lists of scalars with ``; `` so a sheet
stays readable; anything deeper is written as compact JSON in its cell.
"""

from __future__ import annotations

import csv
import io
import json
import os
import shutil
import sys
from typing import IO, Any, Dict, Iterable, Iterator, List, Optional, Sequence

FORMATS = ("json", "jsonl", "csv", "table")


def guess_format(path: Optional[str], default: str = "table") -> str:
    """Pick the format from the file extension (``.csv``, ``.jsonl``, ``.json``)."""
    if not path or path == "-":
        return default
    ext = os.path.splitext(path)[1].lower().lstrip(".")
    if ext == "ndjson":
        return "jsonl"
    return ext if ext in ("json", "jsonl", "csv") else "json"


def flatten(row: Dict[str, Any], prefix: str = "") -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in row.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict):
            out.update(flatten(value, f"{name}."))
        elif isinstance(value, list):
            if all(not isinstance(v, (dict, list)) for v in value):
                out[name] = "; ".join("" if v is None else str(v) for v in value)
            else:
                out[name] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        else:
            out[name] = value
    return out


def _columns(rows: Sequence[Dict[str, Any]]) -> List[str]:
    seen: Dict[str, None] = {}
    for row in rows:
        for key in row:
            seen.setdefault(key, None)
    return list(seen)


def write_json(rows: Iterable[Dict[str, Any]], fh: IO[str]) -> int:
    data = list(rows)
    json.dump(data, fh, ensure_ascii=False, indent=2, default=str)
    fh.write("\n")
    return len(data)


def write_jsonl(rows: Iterable[Dict[str, Any]], fh: IO[str]) -> int:
    n = 0
    for row in rows:
        fh.write(json.dumps(row, ensure_ascii=False, default=str))
        fh.write("\n")
        n += 1
    return n


def write_csv(rows: Iterable[Dict[str, Any]], fh: IO[str]) -> int:
    flat = [flatten(r) for r in rows]
    if not flat:
        return 0
    writer = csv.DictWriter(fh, fieldnames=_columns(flat), extrasaction="ignore")
    writer.writeheader()
    for row in flat:
        writer.writerow({k: "" if v is None else v for k, v in row.items()})
    return len(flat)


def _cell(value: Any, width: int) -> str:
    text = "" if value is None else str(value)
    text = " ".join(text.split())
    return text if len(text) <= width else text[: max(1, width - 1)] + "…"


def write_table(rows: Iterable[Dict[str, Any]], fh: IO[str], columns: Optional[Sequence[str]] = None,
                max_width: Optional[int] = None) -> int:
    """A compact table for the terminal: the given columns, each cut to fit."""
    flat = [flatten(r) for r in rows]
    if not flat:
        fh.write("No results.\n")
        return 0
    cols = [c for c in (columns or _columns(flat)) if any(c in r for r in flat)]
    total = max_width or shutil.get_terminal_size((120, 20)).columns
    width = max(8, (total - 2 * (len(cols) - 1)) // max(1, len(cols)))
    widths = {c: min(width, max(len(c), *(len(_cell(r.get(c), width)) for r in flat))) for c in cols}
    fh.write("  ".join(c.ljust(widths[c]) for c in cols).rstrip() + "\n")
    fh.write("  ".join("-" * widths[c] for c in cols) + "\n")
    for row in flat:
        fh.write("  ".join(_cell(row.get(c), widths[c]).ljust(widths[c]) for c in cols).rstrip() + "\n")
    return len(flat)


def write(rows: Iterable[Dict[str, Any]], path: Optional[str] = None, fmt: Optional[str] = None,
          columns: Optional[Sequence[str]] = None) -> int:
    """Write rows to ``path`` (or stdout) and return how many were written."""
    fmt = fmt or guess_format(path)
    if fmt not in FORMATS:
        raise ValueError(f"unknown format {fmt!r}, expected one of {', '.join(FORMATS)}")
    if path and path != "-":
        directory = os.path.dirname(os.path.abspath(path))
        os.makedirs(directory, exist_ok=True)
        # newline="" lets the csv module write \r\n itself, as RFC 4180 asks.
        with open(path, "w", encoding="utf-8", newline="" if fmt == "csv" else None) as fh:
            return _dispatch(rows, fh, fmt, columns)
    return _dispatch(rows, sys.stdout, fmt, columns)


def _dispatch(rows: Iterable[Dict[str, Any]], fh: IO[str], fmt: str, columns: Optional[Sequence[str]]) -> int:
    if fmt == "json":
        return write_json(rows, fh)
    if fmt == "jsonl":
        return write_jsonl(rows, fh)
    if fmt == "csv":
        return write_csv(rows, fh)
    return write_table(rows, fh, columns)


def write_object(data: Dict[str, Any], path: Optional[str] = None) -> int:
    """Write one JSON object (a whole API response) to ``path`` or stdout."""
    text = json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n"
    if path and path != "-":
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        sys.stdout.write(text)
    return 1


def to_csv_string(rows: Iterable[Dict[str, Any]]) -> str:
    buf = io.StringIO()
    write_csv(rows, buf)
    return buf.getvalue()


def iter_rows(rows: Iterable[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
    yield from rows
