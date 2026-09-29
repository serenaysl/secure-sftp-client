# Security Design Notes

## Threat model

The client is designed to reduce common risks during remote file transfer:

1. **Network eavesdropping**
   - Mitigation: SFTP over SSH encrypts the session.

2. **Credential exposure in source code**
   - Mitigation: passwords are requested interactively with `getpass`.
   - No password is stored in the source code.

3. **Man-in-the-middle attack**
   - Mitigation: unknown SSH server host keys are rejected.
   - The user must trust a server key before connection.

4. **File corruption**
   - Mitigation: SHA-256 can be used to compare local copies before/after transfer.

5. **Resource/session leakage**
   - Mitigation: SFTP and SSH sessions are closed in `finally` / context-manager logic.

## Why RejectPolicy is used

Paramiko supports automatically accepting previously unseen host keys, but doing so
removes an important identity check. This project uses `RejectPolicy()` so an
attacker cannot simply present a new SSH host key and be silently trusted.

## Password vs key authentication

Password authentication is included for compatibility and classroom demonstration.
SSH public-key authentication is also supported and is preferable when correctly
managed.

Private keys should:
- never be committed to Git,
- be protected with appropriate filesystem permissions,
- preferably use a passphrase.

## Wireshark expectation

A capture should reveal SSH traffic to TCP port 22. It should not reveal the
transferred file contents in plaintext. Network metadata remains observable.
