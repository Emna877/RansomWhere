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

## Sandbox Setup And Test Plan

1. Create the sandbox directory:

```powershell
New-Item -ItemType Directory -Force -Path "C:\RansomLab\sandbox"
```

2. Add sample files for testing:

```powershell
"hello world" | Set-Content "C:\RansomLab\sandbox\sample1.txt"
"demo data" | Set-Content "C:\RansomLab\sandbox\sample2.log"
```

3. Run encryption:

```powershell
python safe_ransomware_sim.py encrypt
```

4. Verify expected encryption results:

```powershell
Get-ChildItem "C:\RansomLab\sandbox" -Recurse
```

You should see:
- `sample1.txt.locked`
- `sample2.log.locked`
- `README.txt`

5. Run decryption:

```powershell
python safe_ransomware_sim.py decrypt
```

6. Verify restore results:

```powershell
Get-ChildItem "C:\RansomLab\sandbox" -Recurse
```

You should see files restored to original names:
- `sample1.txt`
- `sample2.log`

## Important

- Educational use only
- No system-level operations
- No network activity
- No persistence behavior
