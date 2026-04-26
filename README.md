# Safe Ransomware Simulation (Educational)

This project contains a **safe** Python script that simulates ransomware behavior
for training and lab use only.

## Script

- `safe_ransomware_sim.py`

## Hardcoded Sandbox

The script only operates on:

- `C:\\RansomLab\\sandbox`

It includes path checks to avoid touching files outside this directory.

## Features

- Traverses files in the sandbox
- Reversible XOR encryption/decryption
- Adds `.locked` extension during encrypt mode
- Removes `.locked` extension during decrypt mode
- Skips already encrypted files in encrypt mode
- Creates a fake ransom note: `README.txt`
- Prints logs for every action

## Usage

```powershell
python safe_ransomware_sim.py encrypt
python safe_ransomware_sim.py decrypt
```

## Important

- Educational use only
- No system-level operations
- No network activity
- No persistence behavior
