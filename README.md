# Secure SFTP Client Assignment

## Purpose

This project demonstrates secure file transfer using SFTP (SSH File Transfer Protocol).
SFTP runs over SSH and protects file contents and authentication traffic in transit.

## Features

- Connect to an SFTP server over SSH.
- Strict host-key verification.
- Passwords are entered securely and are not hard-coded.
- Optional SSH private-key authentication.
- List remote files.
- Upload files.
- Download files.
- Create remote directories.
- Calculate SHA-256 hashes for integrity checks.
- Cleanly close SSH/SFTP sessions.
- Error handling for authentication, host-key, and network failures.

## Requirements

- Windows 10/11
- Python 3.10+
- VS Code
- PowerShell
- Wireshark
- Access to an SFTP/SSH server

## Installation

Open PowerShell in this project folder:

```powershell
python --version
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\.venv\Scripts\Activate.ps1
```

## Host-key setup

The client deliberately rejects unknown server keys.

For an SSH server you control, first obtain and verify its public host-key fingerprint
through a trusted method (for example, directly from the server administrator).

On Windows OpenSSH, a normal SSH connection can populate your user known_hosts file:

```powershell
ssh username@SERVER_IP
```

Before accepting the fingerprint, compare it with the fingerprint supplied by the
server administrator.

You can then use the normal system known_hosts file, or provide a dedicated file:

```powershell
python sftp_client.py --host SERVER_IP --username USER --known-hosts .\known_hosts list .
```

DO NOT use AutoAddPolicy in a security-focused assignment because silently trusting a
new key weakens protection against man-in-the-middle attacks.

## Usage

### List files

```powershell
python sftp_client.py --host SERVER_IP --username USER list .
```

### Upload

First create a test file:

```powershell
"Cybersecurity SFTP test file" | Out-File test.txt
```

Then upload:

```powershell
python sftp_client.py --host SERVER_IP --username USER upload .\test.txt /remote/path/test.txt
```

### Download

```powershell
python sftp_client.py --host SERVER_IP --username USER download /remote/path/test.txt .\downloaded-test.txt
```

### SSH private key authentication

```powershell
python sftp_client.py --host SERVER_IP --username USER --key-file "$env:USERPROFILE\.ssh\id_ed25519" list .
```

### Integrity check

```powershell
python sftp_client.py --host SERVER_IP --username USER hash .\test.txt
python sftp_client.py --host SERVER_IP --username USER hash .\downloaded-test.txt
```

If the two files are intended to be identical, matching SHA-256 hashes demonstrate
that their contents are identical.

## Wireshark demonstration

1. Start Wireshark.
2. Capture the active network interface.
3. Run an SFTP command from PowerShell.
4. Stop the capture.
5. Apply this display filter:

```text
tcp.port == 22
```

What to show in screenshots:

- TCP connection to port 22.
- SSH protocol traffic.
- Packet payloads are not readable as the uploaded/downloaded file contents.
- The file text and password should not appear in plaintext.

Important security observation:
SFTP encrypts application data, but packet metadata such as IP addresses, port 22,
timing, and packet sizes can still be visible.

## Suggested demonstration sequence

1. Show the source code in VS Code.
2. Show host-key verification code.
3. Start Wireshark capture.
4. Run `list`.
5. Upload `test.txt`.
6. Download it under a different filename.
7. Compare SHA-256 hashes.
8. Stop Wireshark capture.
9. Filter by `tcp.port == 22`.
10. Show that the actual file contents are not visible.

## Security limitations

- SHA-256 verifies local file equality but does not by itself prove who created a file.
- Host-key fingerprints must be verified using a trusted source before first use.
- SFTP protects data in transit; local endpoint security is still required.
- Password authentication can be used, but SSH keys are preferable for many deployments.

## Ethical use

Use this client only with servers and accounts you own or are authorized to access.
