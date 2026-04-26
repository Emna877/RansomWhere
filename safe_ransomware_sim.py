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

# Hardcoded sandbox path. The script must never process anything outside this directory.
SANDBOX_DIR = Path(r"C:\RansomLab\sandbox")
LOCKED_EXTENSION = ".locked"
RANSOM_NOTE_NAME = "README.txt"
XOR_KEY = b"EDU_SAFE_KEY_2026"


def log(message: str) -> None:
    """Print a standardized log message."""
    print(f"[SIM] {message}")


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

    note_text = (
        "Your files have been locked in this EDUCATIONAL simulation.\n"
        "This is a harmless training exercise.\n"
        "Run this script in decrypt mode to restore your files.\n"
        "No payment is needed.\n"
    )

    try:
        note_path.write_text(note_text, encoding="utf-8")
        log(f"Created ransom note: {note_path}")
    except Exception as exc:
        log(f"Failed to create ransom note {note_path}: {exc}")


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
        "skipped_note": 0,
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

            if filename == RANSOM_NOTE_NAME:
                log(f"Skipping ransom note file: {file_path}")
                stats["skipped_note"] += 1
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
        log("Troubleshoot: nothing encrypted. Files may already end with .locked, or only README.txt is present.")

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
    log(f"Skipped ransom note: {stats['skipped_note']}")
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
        stats = process_directory("encrypt")
        create_ransom_note()
        log_summary("encrypt", stats)
        log("Encryption simulation complete.")
    elif args.mode == "decrypt":
        log("Starting decryption simulation...")
        stats = process_directory("decrypt")
        log_summary("decrypt", stats)
        log("Decryption simulation complete.")


if __name__ == "__main__":
    main()
