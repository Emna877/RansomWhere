"""
RansomWhere — Anomaly Detector Extension
=========================================
Monitors the sandbox directory in real-time and flags ransomware-like behavior.

Detection signals:
  1. Rapid file rename/extension change (e.g., .txt → .txt.hyenc)
  2. High-entropy file content (encrypted data has near-max Shannon entropy)
  3. Mass file modification in a short window
  4. Appearance of known ransom-note filenames
  5. Unusual write-volume bursts (bytes written per second)

Usage (standalone monitor):
    python anomaly_detector.py --watch C:\\RansomLab\\sandbox

Usage (import into script.py):
    from anomaly_detector import AnomalyDetector
    detector = AnomalyDetector(sandbox_path)
    detector.start()
    ...
    detector.stop()
    report = detector.report()
"""

from __future__ import annotations

import math
import os
import sys
import time
import threading
import argparse
import json
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

ENTROPY_THRESHOLD      = 7.2     # bits/byte  (max = 8.0; compressed/encrypted ≥ 7.5)
MASS_MOD_WINDOW_SEC    = 10      # seconds to look back for "mass modification"
MASS_MOD_THRESHOLD     = 3       # files modified within the window → alert
WRITE_BURST_THRESHOLD  = 512_000 # bytes/sec that triggers a write-burst alert
RANSOM_NOTE_NAMES      = {
    "note.txt", "read_me.txt", "how_to_decrypt.txt",
    "decrypt_files.txt", "ransom.txt", "!!!readme!!!.txt",
    "your_files_are_encrypted.txt",
}
SUSPICIOUS_EXTENSIONS  = {".hyenc", ".locked", ".encrypted", ".enc", ".crypt", ".crypto"}
POLL_INTERVAL_SEC      = 0.5     # how often to scan the directory


# ──────────────────────────────────────────────
# Data structures
# ──────────────────────────────────────────────

@dataclass
class AnomalyEvent:
    timestamp: str
    kind: str          # "entropy" | "mass_mod" | "rename" | "ransom_note" | "write_burst"
    severity: str      # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    path: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.timestamp}] [{self.severity:8s}] {self.kind:12s}  {self.path}  — {self.detail}"


@dataclass
class DetectorReport:
    started_at: str
    stopped_at: str
    total_events: int
    events_by_severity: dict
    events: list[dict]


# ──────────────────────────────────────────────
# Core helpers
# ──────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Return Shannon entropy (bits/byte) for the given byte sequence."""
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    n = len(data)
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return entropy


def is_suspicious_extension(path: Path) -> bool:
    return path.suffix.lower() in SUSPICIOUS_EXTENSIONS or \
           any(path.name.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)


def is_ransom_note(path: Path) -> bool:
    return path.name.lower() in RANSOM_NOTE_NAMES


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ──────────────────────────────────────────────
# Detector
# ──────────────────────────────────────────────

class AnomalyDetector:
    """
    Polls a directory tree and emits AnomalyEvents for ransomware-like behaviour.
    Thread-safe: start() / stop() can be called from any thread.
    """

    def __init__(self, sandbox: Path, log_path: Path | None = None, verbose: bool = True):
        self.sandbox     = Path(sandbox)
        self.log_path    = log_path
        self.verbose     = verbose

        self._events: list[AnomalyEvent] = []
        self._lock       = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

        # Snapshot: path → (mtime, size)
        self._snapshot: dict[str, tuple[float, int]] = {}
        # Sliding window of modification timestamps for mass-mod detection
        self._mod_times: deque[float] = deque()
        self._started_at: str = ""
        self._stopped_at: str = ""

    # ── Public API ─────────────────────────────

    def start(self) -> None:
        """Begin monitoring in a background thread."""
        self._started_at = now_str()
        self._stop_event.clear()
        self._snapshot = self._take_snapshot()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="AnomalyDetector")
        self._thread.start()
        self._log_raw(f"[{now_str()}] AnomalyDetector started — watching: {self.sandbox}")

    def stop(self) -> None:
        """Signal the monitor to stop and wait for it to finish."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._stopped_at = now_str()
        self._log_raw(f"[{now_str()}] AnomalyDetector stopped.")

    def report(self) -> DetectorReport:
        """Return a structured report of all detected anomalies."""
        with self._lock:
            by_sev: dict[str, int] = {}
            for e in self._events:
                by_sev[e.severity] = by_sev.get(e.severity, 0) + 1
            return DetectorReport(
                started_at=self._started_at,
                stopped_at=self._stopped_at,
                total_events=len(self._events),
                events_by_severity=by_sev,
                events=[asdict(e) for e in self._events],
            )

    def print_report(self) -> None:
        r = self.report()
        print("\n" + "═" * 70)
        print("  RANSOMWHERE — ANOMALY DETECTOR REPORT")
        print("═" * 70)
        print(f"  Monitoring period : {r.started_at}  →  {r.stopped_at}")
        print(f"  Total anomalies   : {r.total_events}")
        for sev, cnt in sorted(r.events_by_severity.items()):
            print(f"  {sev:10s}: {cnt}")
        print("─" * 70)
        if not r.events:
            print("  No anomalies detected.")
        else:
            for e in r.events:
                print(f"  [{e['timestamp']}] [{e['severity']:8s}] {e['kind']:12s}")
                print(f"    Path   : {e['path']}")
                print(f"    Detail : {e['detail']}")
                print()
        print("═" * 70)

    def save_report_json(self, out_path: Path) -> None:
        r = self.report()
        out_path.write_text(json.dumps(asdict(r), indent=2), encoding="utf-8")
        print(f"[AnomalyDetector] Report saved → {out_path}")

    # ── Internal ───────────────────────────────

    def _monitor_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._poll()
            except Exception as exc:
                self._log_raw(f"[{now_str()}] [ERROR] Polling error: {exc}")
            self._stop_event.wait(POLL_INTERVAL_SEC)

    def _poll(self) -> None:
        new_snapshot = self._take_snapshot()
        now = time.monotonic()

        # Compare new snapshot against old
        for path_str, (mtime, size) in new_snapshot.items():
            path = Path(path_str)
            prev = self._snapshot.get(path_str)

            # --- New file appeared ---
            if prev is None:
                # Ransom note?
                if is_ransom_note(path):
                    self._emit(AnomalyEvent(
                        timestamp=now_str(), kind="ransom_note", severity="CRITICAL",
                        path=path_str,
                        detail=f"Ransom note '{path.name}' appeared in sandbox.",
                    ))
                # Suspicious extension on a new file?
                elif is_suspicious_extension(path):
                    self._emit(AnomalyEvent(
                        timestamp=now_str(), kind="rename", severity="HIGH",
                        path=path_str,
                        detail=f"New file with suspicious extension '{path.suffix}' detected.",
                    ))
                    # Also check entropy of new encrypted file
                    self._check_entropy(path)

            # --- Existing file was modified ---
            elif mtime != prev[0] or size != prev[1]:
                self._mod_times.append(now)
                # Purge stale timestamps
                cutoff = now - MASS_MOD_WINDOW_SEC
                while self._mod_times and self._mod_times[0] < cutoff:
                    self._mod_times.popleft()

                # Mass-modification check
                if len(self._mod_times) >= MASS_MOD_THRESHOLD:
                    self._emit(AnomalyEvent(
                        timestamp=now_str(), kind="mass_mod", severity="HIGH",
                        path=path_str,
                        detail=(
                            f"{len(self._mod_times)} files modified within "
                            f"{MASS_MOD_WINDOW_SEC}s window."
                        ),
                    ))

                # Write-burst check (bytes/sec)
                dt = mtime - prev[0] if mtime != prev[0] else POLL_INTERVAL_SEC
                delta_bytes = abs(size - prev[1])
                bps = delta_bytes / max(dt, 0.001)
                if bps > WRITE_BURST_THRESHOLD:
                    self._emit(AnomalyEvent(
                        timestamp=now_str(), kind="write_burst", severity="MEDIUM",
                        path=path_str,
                        detail=f"Write rate {bps/1024:.1f} KB/s exceeds threshold.",
                    ))

                # Entropy check on modified file
                if is_suspicious_extension(path):
                    self._check_entropy(path)

        # Check for files that vanished (renamed/deleted during encrypt)
        for path_str in list(self._snapshot.keys()):
            if path_str not in new_snapshot:
                path = Path(path_str)
                # If it vanished and a .hyenc twin exists, that's a rename
                candidate = Path(path_str + SUSPICIOUS_EXTENSIONS.__iter__().__next__())
                # Just flag vanished non-key files
                if not path.name.startswith("private_key") and path.suffix not in SUSPICIOUS_EXTENSIONS:
                    encrypted_twin = Path(str(path) + ".hyenc")
                    if str(encrypted_twin) in new_snapshot:
                        self._emit(AnomalyEvent(
                            timestamp=now_str(), kind="rename", severity="HIGH",
                            path=path_str,
                            detail=f"File renamed to '{encrypted_twin.name}' (in-place encryption detected).",
                        ))

        self._snapshot = new_snapshot

    def _check_entropy(self, path: Path) -> None:
        try:
            data = path.read_bytes()
            if not data:
                return
            # Sample up to 64 KB for speed
            sample = data[:65536]
            h = shannon_entropy(sample)
            if h >= ENTROPY_THRESHOLD:
                self._emit(AnomalyEvent(
                    timestamp=now_str(), kind="entropy", severity="HIGH",
                    path=str(path),
                    detail=f"Shannon entropy = {h:.3f} bits/byte (threshold {ENTROPY_THRESHOLD}) — likely encrypted.",
                ))
        except (OSError, PermissionError):
            pass

    def _take_snapshot(self) -> dict[str, tuple[float, int]]:
        snap: dict[str, tuple[float, int]] = {}
        try:
            for p in self.sandbox.rglob("*"):
                if p.is_file():
                    try:
                        st = p.stat()
                        snap[str(p)] = (st.st_mtime, st.st_size)
                    except OSError:
                        pass
        except OSError:
            pass
        return snap

    def _emit(self, event: AnomalyEvent) -> None:
        with self._lock:
            # Deduplicate: skip if same kind+path was emitted in the last 3 seconds
            for existing in reversed(self._events[-20:]):
                if existing.kind == event.kind and existing.path == event.path:
                    try:
                        ts_existing = datetime.strptime(existing.timestamp, "%Y-%m-%d %H:%M:%S")
                        ts_new      = datetime.strptime(event.timestamp,    "%Y-%m-%d %H:%M:%S")
                        if abs((ts_new - ts_existing).total_seconds()) < 3:
                            return
                    except ValueError:
                        pass
            self._events.append(event)

        if self.verbose:
            print(event)
        self._log_raw(str(event))

    def _log_raw(self, line: str) -> None:
        if self.log_path:
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError:
                pass


# ──────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="RansomWhere Anomaly Detector — real-time ransomware behaviour monitor."
    )
    parser.add_argument(
        "--watch", default=r"C:\Users\zeine\Desktop\RansomWhere",
        help="Sandbox directory to monitor (default: C:\\RansomLab\\sandbox).",
    )
    parser.add_argument(
        "--duration", type=int, default=0,
        help="Stop after N seconds (0 = run until Ctrl-C).",
    )
    parser.add_argument(
        "--report", default="",
        help="Save JSON report to this path when done.",
    )
    parser.add_argument(
        "--log", default="",
        help="Append detector events to this log file.",
    )
    args = parser.parse_args()

    sandbox  = Path(args.watch)
    log_path = Path(args.log) if args.log else None

    if not sandbox.exists():
        print(f"[ERROR] Sandbox path not found: {sandbox}")
        sys.exit(1)

    detector = AnomalyDetector(sandbox, log_path=log_path, verbose=True)
    detector.start()

    print(f"\n  RansomWhere Anomaly Detector active — watching: {sandbox}")
    print("  Press Ctrl-C to stop.\n")

    try:
        if args.duration > 0:
            time.sleep(args.duration)
        else:
            while True:
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Stopping detector…")

    detector.stop()
    detector.print_report()

    if args.report:
        detector.save_report_json(Path(args.report))


if __name__ == "__main__":
    main()