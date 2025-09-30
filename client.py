"""Module implementing IRC client functionality."""

from typing import Optional, Literal
import socket
import queue
import enum
import exceptions


BUFFER_SIZE = 1024


class ClientServiceMessages(str, enum.Enum):
    CONNECTION_ERROR = "connection_error"
    RECEIVER_STOPPED = "receiver_stopped"
    SERVER_CLOSED_CONNECTION = "server_closed_connection"


class ZavrClient:
    """Implements class for working with single connection with single IRC server
    asynchroniously. Several objects can be created fron this class to represent
    diferent IRC server connections.
    """

    def __init__(
        self,
        host: str,
        port: int = 6667,
        tls: bool = False,
        errors: Optional[Literal["ignore", "replace"]] = "ignore",
    ) -> None:
        """Initialize client with a given connection data.

        Args:
            host (str): IRC server's host. It's either ip address or domain name.
            port (int): IRC server's port. It's a number from 0 to 65535. Defaults to 6667.
            tls (bool, optional): Should client use TLS-handshake or not. Defaults to False.
        """

        self._host = host
        self._port = port
        self._tls = tls
        self._errors = errors

        self._socket: Optional[socket.SocketType] = None

        self.receive_queue: queue.Queue[str] = queue.Queue()
        self.send_queue: queue.Queue[str] = queue.Queue()

    def connect(self):
        """Connects to an IRC server given at initialization."""

        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(180.0)
            self._socket.connect((self._host, self._port))
        except OSError as e:
            raise exceptions.ClientConnectionError(
                "Something went wrong while connection to a server!"
            ) from e

    def _receive_task(self):
        """Receives messages from socket and puts them in queue"""

        if self._socket is None:
            raise exceptions.ClientIsNotConnectedError("Client is not connected!")

        buffer = b""

        while True:

            try:
                data = self._socket.recv(BUFFER_SIZE)

                if not data:
                    print("Server closed connection.")
                    self.receive_queue.put(
                        ClientServiceMessages.SERVER_CLOSED_CONNECTION
                    )
                    break

            except (socket.error, OSError):
                print("Socket error during receive!")
                self.receive_queue.put(ClientServiceMessages.CONNECTION_ERROR)
                break

            buffer += data

            while (position := buffer.find(b"\r\n")) != -1:
                message, buffer = buffer[:position], buffer[position + 2 :]
                self.receive_queue.put(message.decode("utf-8", errors=self._errors))

        self.receive_queue.put(ClientServiceMessages.RECEIVER_STOPPED)

    def _send_task(self): ...

    def start(self): ...
