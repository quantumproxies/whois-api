"""Where the login lives: one JSON file per user, shared by every QuanticData tool.

``~/.config/quanticdata/credentials.json`` (``%APPDATA%\\quanticdata`` on Windows,
``$XDG_CONFIG_HOME`` when set), mode 0600 inside a 0700 directory. Writes go
through a temporary file and ``os.replace`` so a crash never leaves half a file.

Refresh tokens rotate and the server revokes the whole grant when an old one is
presented twice, so two processes refreshing at the same moment would sign the
user out. ``locked()`` serialises refreshes across processes with an OS file
lock; the caller re-reads the file once it holds the lock.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
import time
from typing import Any, Dict, Iterator, Optional

ENV_DIR = "QUANTICDATA_CONFIG_DIR"


def config_dir() -> str:
    if os.environ.get(ENV_DIR):
        return os.environ[ENV_DIR]
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~\\AppData\\Roaming")
        return os.path.join(base, "quanticdata")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "quanticdata")


def credentials_path() -> str:
    return os.path.join(config_dir(), "credentials.json")


def _ensure_dir() -> str:
    d = config_dir()
    os.makedirs(d, mode=0o700, exist_ok=True)
    if sys.platform != "win32":
        with contextlib.suppress(OSError):
            os.chmod(d, 0o700)
    return d


def load() -> Dict[str, Any]:
    try:
        with open(credentials_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {}


def save(data: Dict[str, Any]) -> None:
    d = _ensure_dir()
    fd, tmp = tempfile.mkstemp(prefix=".credentials.", dir=d)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        if sys.platform != "win32":
            os.chmod(tmp, 0o600)
        os.replace(tmp, credentials_path())
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def get_profile(issuer: str) -> Optional[Dict[str, Any]]:
    profile = load().get("profiles", {}).get(issuer)
    return profile if isinstance(profile, dict) else None


def put_profile(issuer: str, profile: Optional[Dict[str, Any]]) -> None:
    data = load()
    profiles = data.setdefault("profiles", {})
    if profile is None:
        profiles.pop(issuer, None)
    else:
        profiles[issuer] = profile
    save(data)


@contextlib.contextmanager
def locked(timeout: float = 30.0) -> Iterator[None]:
    """Hold an exclusive lock on ``credentials.lock`` for the duration of the block."""
    path = os.path.join(_ensure_dir(), "credentials.lock")
    fh = open(path, "a+")
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                _lock(fh)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"another process holds {path}")
                time.sleep(0.1)
        yield
    finally:
        with contextlib.suppress(OSError):
            _unlock(fh)
        fh.close()


if sys.platform == "win32":  # pragma: no cover - exercised on Windows CI
    import msvcrt

    def _lock(fh: Any) -> None:
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)

    def _unlock(fh: Any) -> None:
        fh.seek(0)
        msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock(fh: Any) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)

    def _unlock(fh: Any) -> None:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
