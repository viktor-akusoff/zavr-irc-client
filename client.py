"""Module implementing IRC client functionality."""

from typing import Optional
import socket
import exceptions


class ZavrClient:
    """Implements class for working with single connection with single IRC server
    asynchroniously. Several objects can be created fron this class to represent
    diferent IRC server connections.
    """

    def __init__(self, host: str, port: int = 6667, tls: bool = False) -> None:
        """Initialize client with a given connection data.

        Args:
            host (str): IRC server's host. It's either ip address or domain name.
            port (int): IRC server's port. It's a number from 0 to 65535. Defaults to 6667.
            tls (bool, optional): Should client use TLS-handshake or not. Defaults to False.
        """

        self._host = host
        self._port = port
        self._tls = tls

        self._socket: Optional[socket.SocketType] = None

    def connect(self):
        """Connects to an IRC server given at initialization."""
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.connect((self._host, self._port))
        except OSError as e:
            raise exceptions.ClientConnectionError(
                "Something went wrong while connection to a server!"
            ) from e
