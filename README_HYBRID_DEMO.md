# Hybrid Encryption Demo (Sandbox-Only)

This document describes the safe hybrid encryption demo implemented in `safe_ransomware_sim2.py`.

## Overview

The script demonstrates envelope encryption on **one file at a time**:

- AES-256-GCM encrypts file contents
- RSA-2048 (OAEP-SHA256) encrypts the AES session key

The encrypted AES key is stored in the output file header and is recovered with the RSA private key during decryption.

## Safety Boundaries

The demo is intentionally restricted to:

- `C:\RansomLab\sandbox`

Safety behavior:

- Refuses any file path outside sandbox
- Requires explicit consent (unless `--yes` is used)
- No directory traversal
- No system-level operations
- No persistence behavior

## Requirements

Install dependencies:

```powershell
C:/Python313/python.exe -m pip install -r requirements.txt
```

`requirements.txt` includes:

- `cryptography>=42.0.0`

## Commands

### 1. Generate RSA key pair

```powershell
C:/Python313/python.exe safe_ransomware_sim2.py gen-keys
```

Creates:

- `C:\RansomLab\sandbox\keys\public_key.pem`
- `C:\RansomLab\sandbox\keys\private_key.pem`

### 2. Encrypt one file

```powershell
C:/Python313/python.exe safe_ransomware_sim2.py encrypt --file C:/RansomLab/sandbox/sample.txt
```

Output file:

- `sample.txt.hyenc`

### 3. Decrypt one file

```powershell
C:/Python313/python.exe safe_ransomware_sim2.py decrypt --file C:/RansomLab/sandbox/sample.txt.hyenc
```

Output file:

- `sample.txt.restored`

## Optional Flags

Skip interactive confirmation prompt:

```powershell
--yes
```

Use custom key paths (must still be inside sandbox):

- Encrypt: `--public-key <path>`
- Decrypt: `--private-key <path>`

## Encrypted File Structure

The `.hyenc` file format is:

1. Magic bytes: `HYBDEMO1` (8 bytes)
2. Wrapped key length (2 bytes, big-endian)
3. AES-GCM nonce (12 bytes)
4. RSA-wrapped AES key (variable)
5. AES-GCM ciphertext + auth tag (variable)

## Logging

Runtime logs are written to:

- `C:\RansomLab\sandbox\hybrid_demo.log`

## Troubleshooting

- `Blocked path outside sandbox`: move file/key into `C:\RansomLab\sandbox`
- `Input already appears encrypted`: do not re-encrypt `.hyenc` files
- `Invalid file magic`: file was not created by this demo format
- Import errors for `cryptography`: reinstall with `pip install -r requirements.txt`
