"""
Secure SFTP Client
Cybersecurity assignment demonstration.

Features:
- SSH/SFTP encrypted transport via Paramiko
- Strict server host-key validation
- Password input hidden with getpass
- Optional SSH private-key authentication
- Upload, download, list, mkdir and file hash commands
- SHA-256 local integrity verification support
- No hard-coded credentials
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import sys
from pathlib import Path

import paramiko


def sha256_file(path: str | Path) -> str:
    """Return SHA-256 digest of a local file."""
    digest = hashlib.sha256()
    with open(path, "rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class SecureSFTPClient:
    def __init__(
        self,
        host: str,
        username: str,
        port: int = 22,
        known_hosts: str | None = None,
    ) -> None:
        self.host = host
        self.username = username
        self.port = port
        self.known_hosts = known_hosts
        self.ssh: paramiko.SSHClient | None = None
        self.sftp: paramiko.SFTPClient | None = None

    def connect(
        self,
        password: str | None = None,
        key_file: str | None = None,
    ) -> None:
        ssh = paramiko.SSHClient()

        # Load trusted server keys from the operating system.
        ssh.load_system_host_keys()

        # Optionally load a project-specific known_hosts file.
        if self.known_hosts:
            if not Path(self.known_hosts).exists():
                raise FileNotFoundError(
                    f"known_hosts file not found: {self.known_hosts}\n"
                    "Add the trusted server key before connecting."
                )
            ssh.load_host_keys(self.known_hosts)

        # SECURITY: Reject unknown host keys.
        # This helps prevent man-in-the-middle attacks.
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

        connect_kwargs = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
            "timeout": 10,
            "banner_timeout": 10,
            "auth_timeout": 10,
        }

        if key_file:
            connect_kwargs["key_filename"] = key_file
            connect_kwargs["look_for_keys"] = False
            connect_kwargs["allow_agent"] = False
        else:
            connect_kwargs["password"] = password
            connect_kwargs["look_for_keys"] = False
            connect_kwargs["allow_agent"] = False

        ssh.connect(**connect_kwargs)
        self.ssh = ssh
        self.sftp = ssh.open_sftp()

        transport = ssh.get_transport()
        if transport:
            print("[+] Secure SSH connection established")
            print(f"[+] Cipher: {transport.local_cipher}")
            print(f"[+] Server: {self.host}:{self.port}")

    def _require_sftp(self) -> paramiko.SFTPClient:
        if self.sftp is None:
            raise RuntimeError("Not connected to an SFTP server.")
        return self.sftp

    def list_files(self, remote_path: str = ".") -> None:
        sftp = self._require_sftp()
        print(f"\nRemote directory: {remote_path}")
        for attr in sftp.listdir_attr(remote_path):
            print(f"{attr.st_size:>12} bytes  {attr.filename}")

    def upload(self, local_path: str, remote_path: str) -> None:
        sftp = self._require_sftp()
        local = Path(local_path)

        if not local.is_file():
            raise FileNotFoundError(f"Local file not found: {local_path}")

        before_hash = sha256_file(local)
        print(f"[+] Local SHA-256: {before_hash}")
        sftp.put(str(local), remote_path)
        print(f"[+] Uploaded securely: {local} -> {remote_path}")

    def download(self, remote_path: str, local_path: str) -> None:
        sftp = self._require_sftp()
        destination = Path(local_path)
        destination.parent.mkdir(parents=True, exist_ok=True)

        sftp.get(remote_path, str(destination))
        after_hash = sha256_file(destination)

        print(f"[+] Downloaded securely: {remote_path} -> {destination}")
        print(f"[+] Downloaded file SHA-256: {after_hash}")

    def mkdir(self, remote_path: str) -> None:
        sftp = self._require_sftp()
        sftp.mkdir(remote_path)
        print(f"[+] Remote directory created: {remote_path}")

    def close(self) -> None:
        if self.sftp is not None:
            self.sftp.close()
            self.sftp = None

        if self.ssh is not None:
            self.ssh.close()
            self.ssh = None

        print("[+] Connection closed safely")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Secure command-line SFTP client using SSH encryption."
    )
    parser.add_argument("--host", required=True, help="SFTP server hostname or IP")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    parser.add_argument("--username", required=True, help="SSH/SFTP username")
    parser.add_argument(
        "--known-hosts",
        default=None,
        help="Optional path to a trusted known_hosts file",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        help="Optional SSH private key file. If omitted, password authentication is used.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List a remote directory")
    list_parser.add_argument("remote_path", nargs="?", default=".")

    upload_parser = subparsers.add_parser("upload", help="Upload a file")
    upload_parser.add_argument("local_path")
    upload_parser.add_argument("remote_path")

    download_parser = subparsers.add_parser("download", help="Download a file")
    download_parser.add_argument("remote_path")
    download_parser.add_argument("local_path")

    mkdir_parser = subparsers.add_parser("mkdir", help="Create a remote directory")
    mkdir_parser.add_argument("remote_path")

    hash_parser = subparsers.add_parser("hash", help="Calculate local SHA-256")
    hash_parser.add_argument("local_path")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "hash":
        try:
            print(sha256_file(args.local_path))
            return 0
        except OSError as exc:
            print(f"[!] Error: {exc}", file=sys.stderr)
            return 1

    password = None
    if not args.key_file:
        password = getpass.getpass("SFTP password: ")

    client = SecureSFTPClient(
        host=args.host,
        username=args.username,
        port=args.port,
        known_hosts=args.known_hosts,
    )

    try:
        client.connect(password=password, key_file=args.key_file)

        if args.command == "list":
            client.list_files(args.remote_path)
        elif args.command == "upload":
            client.upload(args.local_path, args.remote_path)
        elif args.command == "download":
            client.download(args.remote_path, args.local_path)
        elif args.command == "mkdir":
            client.mkdir(args.remote_path)

        return 0

    except paramiko.BadHostKeyException as exc:
        print(
            "[!] SECURITY ERROR: The server host key does not match the trusted key.\n"
            "    Connection aborted to reduce man-in-the-middle risk.\n"
            f"    Details: {exc}",
            file=sys.stderr,
        )
        return 2

    except paramiko.AuthenticationException:
        print("[!] Authentication failed.", file=sys.stderr)
        return 3

    except (paramiko.SSHException, OSError) as exc:
        print(f"[!] Connection/SFTP error: {exc}", file=sys.stderr)
        return 4

    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
