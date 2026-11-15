"""
ZeroWatch - tamper-evident, rotating JSON-lines log.

Every line stores the SHA-256 of the line before it ("prev") and its own hash, so editing or
removing any earlier line breaks the chain. Two things a plain hash chain cannot see are
handled with a small anchor file kept next to the log:

  truncation   deleting lines from the END leaves a perfectly valid shorter chain, so the anchor
               records how many lines there should be and what the last hash is
  rotation     when the file passes max_bytes it is renamed and a new file starts; the anchor
               records the hash the new file must start from ("genesis")

An attacker who can write both files can still forge both. The head hash is therefore also
exposed on /health and as a Prometheus metric, so an outside monitor keeps an independent copy.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

ZERO = "0" * 64


class ChainLog:
    def __init__(self, path: Path, max_bytes: int = 5_000_000):
        self.path, self.max_bytes = Path(path), max_bytes
        self.anchor_path = self.path.with_suffix(".anchor.json")
        self.lock = threading.Lock()
        self._state = None  # {"genesis", "head", "entries"}; loaded lazily so tests can swap directories

    @staticmethod
    def _hash(prev: str, entry: dict) -> str:
        body = {k: v for k, v in entry.items() if k not in ("hash", "prev")}
        return hashlib.sha256((prev + json.dumps(body, sort_keys=True)).encode()).hexdigest()

    def _load(self) -> dict:
        if self._state is None:
            try:
                self._state = json.loads(self.anchor_path.read_text())
            except (OSError, ValueError):
                lines = self.path.read_text().splitlines() if self.path.exists() else []
                head = ZERO
                if lines:
                    try:
                        head = json.loads(lines[-1])["hash"]
                    except (ValueError, KeyError):
                        pass
                self._state = {"genesis": ZERO, "head": head, "entries": len(lines)}
        return self._state

    def append(self, entry: dict) -> dict:
        """Adds prev/hash to `entry`, writes it, updates the anchor. Never raises on disk errors:
        a read-only disk must not take the API down."""
        with self.lock:
            st = self._load()
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                    self.path.rename(self.path.with_name(f"{self.path.stem}-{int(time.time())}{self.path.suffix}"))
                    st["genesis"], st["entries"] = st["head"], 0
                entry["prev"] = st["head"]
                entry["hash"] = self._hash(st["head"], entry)
                with self.path.open("a") as f:
                    f.write(json.dumps(entry) + "\n")
                st["head"], st["entries"] = entry["hash"], st["entries"] + 1
                self.anchor_path.write_text(json.dumps(st))
            except OSError:
                pass
        return entry

    def read(self, last: int = 3000) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text().splitlines()[-last:]:
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def verify(self) -> dict:
        with self.lock:
            st = dict(self._load())
            lines = self.path.read_text().splitlines() if self.path.exists() else []
        prev = st["genesis"]
        for n, line in enumerate(lines, 1):
            try:
                e = json.loads(line)
                ok = e["prev"] == prev and e["hash"] == self._hash(prev, e)
            except (ValueError, KeyError):
                ok = False
            if not ok:
                return {"valid": False, "entries": len(lines), "broken_at_line": n,
                        "detail": "This entry was edited, or an earlier entry was removed."}
            prev = e["hash"]
        if len(lines) != st["entries"] or prev != st["head"]:
            return {"valid": False, "entries": len(lines), "broken_at_line": len(lines) + 1,
                    "detail": f"The log should hold {st['entries']} entries but has {len(lines)}: "
                              "lines were removed from the end, or added outside the service."}
        return {"valid": True, "entries": len(lines), "head": prev[:16]}

    @property
    def head(self) -> str:
        return self._load()["head"]
