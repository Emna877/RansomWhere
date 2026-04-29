# Hybrid Encryption Demo (Sandbox-Only)

This document describes the safe hybrid encryption demo implemented in `script.py`.

## Overview

The script demonstrates envelope encryption on files inside the sandbox:

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
- No persistence behavior

## Requirements

Install dependencies:

```powershell
C:/Python313/python.exe -m pip install -r requirements.txt
```

## Commands

### 1. Generate RSA key pair

```powershell
C:/Python313/python.exe script.py gen-keys
```

Creates:

- `C:\RansomLab\sandbox\keys\public_key.pem`
- `D:\RansomWhere\private_key.pem`

### 2. Encrypt one file

```powershell
C:/Python313/python.exe script.py encrypt 
```

Output file:

- `sample.txt.hyenc`

### 3. Decrypt one file

```powershell
C:/Python313/python.exe script.py decrypt 
```

Output file:

- `sample.txt`

If you want to target a specific file, pass its path through the sandbox workflow described by the script.

## Optional Flags

Skip interactive confirmation prompt:

```powershell
--yes
```

Use custom key paths (must still be inside sandbox):

- Encrypt: `--public-key <path>`
- Decrypt: `--private-key <path>`

You can also use `--yes` together with either command to skip the confirmation prompt during lab runs.

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
