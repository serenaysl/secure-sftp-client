import os
import socket
import threading
from pathlib import Path

import paramiko


HOST = "127.0.0.1"
PORT = 2222

USERNAME = "student"
PASSWORD = "student123"

BASE_DIR = Path(__file__).parent
SFTP_ROOT = BASE_DIR / "sftp_test_files"
HOST_KEY_FILE = BASE_DIR / "test_server_key"
KNOWN_HOSTS_FILE = BASE_DIR / "known_hosts_test"

SFTP_ROOT.mkdir(exist_ok=True)


def create_host_key():
    """
    Creates a local RSA host key for the test SFTP server.

    If a host key already exists, the same key is reused.
    A matching known_hosts file is also created so the client
    can verify the server identity.
    """
    if HOST_KEY_FILE.exists():
        return paramiko.RSAKey(filename=str(HOST_KEY_FILE))

    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(str(HOST_KEY_FILE))

    known_hosts_line = (
        f"[{HOST}]:{PORT} "
        f"{key.get_name()} "
        f"{key.get_base64()}\n"
    )

    KNOWN_HOSTS_FILE.write_text(
        known_hosts_line,
        encoding="utf-8"
    )

    return key


class Server(paramiko.ServerInterface):
    """
    Simple SSH authentication handler for the local test server.
    """

    def check_auth_password(self, username, password):
        if username == USERNAME and password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED

        return paramiko.OPEN_FAILED_ADMINISTRATIVELY


class LocalSFTPHandle(paramiko.SFTPHandle):
    """
    File handle used by the local SFTP server.
    """

    def stat(self):
        try:
            return paramiko.SFTPAttributes.from_stat(
                os.fstat(self.readfile.fileno())
            )
        except Exception:
            return paramiko.SFTPServer.convert_errno(1)


class LocalSFTPServer(paramiko.SFTPServerInterface):
    """
    Small SFTP server implementation used only for local testing.
    """

    def _local_path(self, path):
        """
        Converts an SFTP path into a safe local path.

        The resolved path must stay inside the SFTP root directory.
        """
        path = path.lstrip("/")

        full_path = (SFTP_ROOT / path).resolve()
        root_path = SFTP_ROOT.resolve()

        if not str(full_path).startswith(str(root_path)):
            raise PermissionError("Invalid path")

        return full_path

    def list_folder(self, path):
        """
        Returns the files inside a remote directory.
        """
        try:
            local_path = self._local_path(path)

            files = []

            for name in os.listdir(local_path):
                file_path = local_path / name

                attributes = paramiko.SFTPAttributes.from_stat(
                    os.stat(file_path)
                )

                attributes.filename = name
                files.append(attributes)

            return files

        except OSError as error:
            return paramiko.SFTPServer.convert_errno(
                error.errno
            )

    def stat(self, path):
        """
        Returns file or directory information.
        """
        try:
            return paramiko.SFTPAttributes.from_stat(
                os.stat(self._local_path(path))
            )

        except OSError as error:
            return paramiko.SFTPServer.convert_errno(
                error.errno
            )

    def lstat(self, path):
        return self.stat(path)

    def open(self, path, flags, attr):
        """
        Opens a file for reading or writing.
        """
        try:
            local_path = self._local_path(path)

            local_path.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            mode = "rb"

            if flags & os.O_WRONLY:
                mode = "wb"

            if flags & os.O_RDWR:
                mode = "r+b"

            if flags & os.O_APPEND:
                mode = "ab"

            if flags & os.O_CREAT and not local_path.exists():
                local_path.touch()

            file_object = open(local_path, mode)

            handle = LocalSFTPHandle(flags)

            handle.filename = str(local_path)
            handle.readfile = file_object
            handle.writefile = file_object

            return handle

        except OSError as error:
            return paramiko.SFTPServer.convert_errno(
                error.errno
            )

    def mkdir(self, path, attr):
        """
        Creates a new remote directory.
        """
        try:
            os.mkdir(self._local_path(path))
            return paramiko.SFTP_OK

        except OSError as error:
            return paramiko.SFTPServer.convert_errno(
                error.errno
            )

    def remove(self, path):
        """
        Removes a remote file.
        """
        try:
            os.remove(self._local_path(path))
            return paramiko.SFTP_OK

        except OSError as error:
            return paramiko.SFTPServer.convert_errno(
                error.errno
            )


def handle_client(client_socket, host_key):
    """
    Handles a single incoming SSH/SFTP connection.
    """
    transport = paramiko.Transport(client_socket)

    transport.add_server_key(host_key)

    transport.set_subsystem_handler(
        "sftp",
        paramiko.SFTPServer,
        LocalSFTPServer
    )

    server = Server()

    try:
        transport.start_server(server=server)

        channel = transport.accept(20)

        if channel is None:
            transport.close()
            return

        while transport.is_active():
            threading.Event().wait(1)

    except Exception as error:
        print("Connection error:", error)

    finally:
        transport.close()


def main():
    """
    Starts the local SFTP test server.
    """
    host_key = create_host_key()

    print("Local SFTP Test Server")
    print("----------------------")
    print(f"Address  : {HOST}")
    print(f"Port     : {PORT}")
    print(f"Username : {USERNAME}")
    print(f"Password : {PASSWORD}")
    print()
    print("SFTP root directory:")
    print(SFTP_ROOT)
    print()
    print("Press Ctrl+C to stop the server.")
    print()

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server_socket.bind((HOST, PORT))
    server_socket.listen(10)

    try:
        while True:
            client_socket, address = server_socket.accept()

            print("New connection:", address)

            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, host_key),
                daemon=True
            )

            thread.start()

    except KeyboardInterrupt:
        print("\nServer stopped.")

    finally:
        server_socket.close()


if __name__ == "__main__":
    main()