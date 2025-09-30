"""Module implementing IRC client functionality."""

from typing import Optional, Literal
import socket
import ssl
import queue
import enum
import dataclasses
import logging
import threading
import exceptions


logger = logging.getLogger(__name__)


class ClientServiceMessages(str, enum.Enum):
    """Describes service messages used by client to notify main app."""

    CONNECTION_ERROR = "connection_error"
    RECEIVER_STOPPED = "receiver_stopped"
    SERVER_CLOSED_CONNECTION = "server_closed_connection"
    MALFUNCTIONING_SERVER = "malfunctioning_server"
    UNKNOWN_ERROR = "unknown_error"


@dataclasses.dataclass
class ClientConfig:
    """Stores configuration for an IRC connection."""

    host: str
    port: int
    tls: bool
    errors: Optional[Literal["ignore", "replace"]]


class ZavrClient:
    """Implements class for working with single connection with single IRC server
    concurrently. Several objects can be created fron this class to represent
    diferent IRC server connections.
    """

    BUFFER_SIZE = 1024
    MAX_BUFFER_SIZE = 4096

    def __init__(self, config: ClientConfig) -> None:
        """Initialize client with a given connection data.

        Args:
            host (str): IRC server's host. It's either ip address or domain name.
            port (int): IRC server's port. It's a number from 0 to 65535. Defaults to 6667.
            tls (bool, optional): Should client use TLS-handshake or not. Defaults to False.
        """

        self._config = config

        self._stop_event = threading.Event()
        self._socket: Optional[socket.SocketType] = None

        self.receive_queue: queue.Queue[str | ClientServiceMessages] = queue.Queue()
        self.send_queue: queue.Queue[str] = queue.Queue()

    def _connect(self):
        """Connects to an IRC server given at initialization."""

        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self._config.tls:
                context = ssl.create_default_context()
                self._socket = context.wrap_socket(
                    self._socket, server_hostname=self._config.host
                )
            self._socket.settimeout(1.0)
            self._socket.connect((self._config.host, self._config.port))
        except OSError as e:
            raise exceptions.ClientConnectionError(
                "Something went wrong while connection to a server!"
            ) from e

    def _receive_task(self):
        """Receives messages from socket and puts them in queue"""

        if self._socket is None:
            raise exceptions.ClientIsNotConnectedError("Client is not connected!")

        buffer = bytearray()

        try:
            while not self._stop_event.is_set():

                try:
                    data = self._socket.recv(self.BUFFER_SIZE)
                except socket.timeout:
                    continue
                except (socket.error, OSError, ssl.SSLError):
                    logger.error(
                        "Socket error during receive on %s:%d!",
                        self._config.host,
                        self._config.port,
                    )
                    self.receive_queue.put(ClientServiceMessages.CONNECTION_ERROR)
                    break
                except Exception:  # pylint: disable=W0718
                    logger.exception(
                        "Unknown error occurred in receiver task for %s:%d!",
                        self._config.host,
                        self._config.port,
                    )
                    self.receive_queue.put(ClientServiceMessages.UNKNOWN_ERROR)
                    break

                if not data:
                    logger.info(
                        "Server (%s:%d) closed connection.",
                        self._config.host,
                        self._config.port,
                    )
                    self.receive_queue.put(
                        ClientServiceMessages.SERVER_CLOSED_CONNECTION
                    )
                    break

                if len(buffer) + len(data) > self.MAX_BUFFER_SIZE:
                    logger.error(
                        "Servers (%s:%d ) messages exceed max buffer size.",
                        self._config.host,
                        self._config.port,
                    )
                    self.receive_queue.put(ClientServiceMessages.MALFUNCTIONING_SERVER)
                    break

                buffer.extend(data)

                while (position := buffer.find(b"\r\n")) != -1:
                    message = buffer[:position]
                    del buffer[: position + 2]

                    self.receive_queue.put(
                        message.decode("utf-8", errors=self._config.errors)
                    )
        finally:
            self.receive_queue.put(ClientServiceMessages.RECEIVER_STOPPED)
            logger.info(
                "Receiver task for %s:%d has stopped.",
                self._config.host,
                self._config.port,
            )

    def _send_task(self): ...

    def start(self): ...

    def stop(self):
        """Stops client and its threads receiving and sending threads."""
        self._stop_event.set()
