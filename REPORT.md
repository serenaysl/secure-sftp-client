# Short Assignment Report

## 1. Objective

The objective of this project is to implement an SFTP client that demonstrates secure
network communication and secure file transfer.

## 2. Technology

The client is written in Python and uses the Paramiko library. Paramiko provides SSH
client functionality and an SFTP subsystem. The program is executed from PowerShell
and can be inspected in VS Code. Wireshark is used to observe the network traffic.

## 3. Implemented functions

The program supports:

- authentication to an SSH/SFTP server,
- remote directory listing,
- secure upload,
- secure download,
- remote directory creation,
- SHA-256 integrity hashing,
- password and SSH private-key authentication.

## 4. Security controls

The most important security control is server host-key verification. The program uses
a reject policy for unknown host keys rather than automatically trusting a new host.
This is intended to reduce man-in-the-middle risk.

Credentials are not hard-coded. When password authentication is selected, `getpass`
is used so that the password is not echoed in the terminal.

All SFTP operations take place inside the encrypted SSH session. SHA-256 hashing is
available to demonstrate that two local file copies have identical contents.

## 5. Wireshark verification

During the experiment, Wireshark can capture the network session and filter it using:

`tcp.port == 22`

The capture shows SSH traffic and connection metadata. The content of the transferred
file is not expected to appear as readable plaintext because SFTP traffic is encrypted
inside SSH.

## 6. Conclusion

The project demonstrates confidentiality through SSH encryption, server identity
verification through SSH host keys, secure credential handling, and basic file
integrity checking. These controls are central to secure file transfer in networked
systems.
