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
    SENDER_STOPPED = "sender_stopped"
    SERVER_CLOSED_CONNECTION = "server_closed_connection"
    MALFUNCTIONING_SERVER = "malfunctioning_server"
    UNKNOWN_ERROR = "unknown_error"


@dataclasses.dataclass
class ClientConfig:
    """Stores configuration for an IRC connection."""

    host: str
    port: int
    tls: bool = False
    encoding: str = "utf-8"
    errors: Optional[Literal["ignore", "replace"]] = "ignore"


@dataclasses.dataclass
class ClientQueues:
    """Stores three client queues used for sending, receiving messages
    and controlling client status.
    """

    receive: queue.Queue[str] = queue.Queue()
    send: queue.Queue[str] = queue.Queue()
    status: queue.Queue[ClientServiceMessages] = queue.Queue()


@dataclasses.dataclass
class ClientState:
    """Stores current client's state."""

    is_running: bool = False
    stop_event: threading.Event = dataclasses.field(default_factory=threading.Event)
    lock: threading.Lock = dataclasses.field(default_factory=threading.Lock)


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
        self._state = ClientState()
        self._socket: Optional[socket.SocketType] = None
        self._receiver_thread: threading.Thread | None = None
        self._sender_thread: threading.Thread | None = None
        self._queues: ClientQueues = ClientQueues()

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
            while not self._state.stop_event.is_set():

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
                    self._queues.status.put(ClientServiceMessages.CONNECTION_ERROR)
                    break
                except Exception:  # pylint: disable=W0718
                    logger.exception(
                        "Unknown error occurred in receiver task for %s:%d!",
                        self._config.host,
                        self._config.port,
                    )
                    self._queues.status.put(ClientServiceMessages.UNKNOWN_ERROR)
                    break

                if not data:
                    logger.info(
                        "Server (%s:%d) closed connection.",
                        self._config.host,
                        self._config.port,
                    )
                    self._queues.status.put(
                        ClientServiceMessages.SERVER_CLOSED_CONNECTION
                    )
                    break

                if len(buffer) + len(data) > self.MAX_BUFFER_SIZE:
                    logger.error(
                        "Servers (%s:%d ) messages exceed max buffer size.",
                        self._config.host,
                        self._config.port,
                    )
                    self._queues.status.put(ClientServiceMessages.MALFUNCTIONING_SERVER)
                    break

                buffer.extend(data)

                while (position := buffer.find(b"\r\n")) != -1:
                    message = buffer[:position]
                    del buffer[: position + 2]

                    self._queues.receive.put(
                        message.decode(
                            self._config.encoding, errors=self._config.errors
                        )
                    )
        finally:
            if not self._state.stop_event.is_set():
                self._state.stop_event.set()
            self._queues.status.put(ClientServiceMessages.RECEIVER_STOPPED)
            logger.info(
                "Receiver task for %s:%d has stopped.",
                self._config.host,
                self._config.port,
            )

    def _send_task(self):

        if self._socket is None:
            raise exceptions.ClientIsNotConnectedError("Client is not connected!")

        try:
            while not self._state.stop_event.is_set():
                try:
                    message_to_send = self._queues.send.get(timeout=1.0)
                except queue.Empty:
                    continue
                encoded_message = (message_to_send + "\r\n").encode(
                    self._config.encoding, errors="replace"
                )

                if len(encoded_message) > 512:
                    logger.warning(
                        "Attempted to send message longer than 512 bytes to %s:%d. Skipping.",
                        self._config.host,
                        self._config.port,
                    )
                    continue
                try:
                    self._socket.sendall(encoded_message)
                except (socket.error, OSError, ssl.SSLError) as e:
                    logger.error(
                        "Socket error during send on %s:%d: %s",
                        self._config.host,
                        self._config.port,
                        e,
                    )
                    self._queues.status.put(ClientServiceMessages.CONNECTION_ERROR)
                    break
                except Exception:  # pylint: disable=W0718
                    logger.exception(
                        "Unknown error occurred in sender task for %s:%d!",
                        self._config.host,
                        self._config.port,
                    )
                    self._queues.status.put(ClientServiceMessages.UNKNOWN_ERROR)
                    break
        finally:
            if not self._state.stop_event.is_set():
                self._state.stop_event.set()
            logger.info(
                "Sender task for %s:%d has stopped.",
                self._config.host,
                self._config.port,
            )
            self._queues.status.put(ClientServiceMessages.SENDER_STOPPED)

    def start(self):
        "Starts sender and receiver threads for client."

        with self._state.lock:
            if self._state.is_running:
                return
            self._state.is_running = True

        self._queues = ClientQueues()
        self._state.stop_event = threading.Event()

        try:
            self._connect()
        except exceptions.ClientConnectionError:
            logger.error(
                "Failed to connect to %s:%d", self._config.host, self._config.port
            )
            self._queues.status.put(ClientServiceMessages.CONNECTION_ERROR)
            return

        self._sender_thread = threading.Thread(target=self._send_task, daemon=True)
        self._receiver_thread = threading.Thread(target=self._receive_task, daemon=True)

        self._sender_thread.start()
        self._receiver_thread.start()

    def stop(self):
        """Stops client and its threads receiving and sending threads."""

        with self._state.lock:
            if not self._state.is_running:
                return
            self._state.is_running = False

        self._state.stop_event.set()

        if self._sender_thread is not None:
            self._sender_thread.join()

        if self._receiver_thread is not None:
            self._receiver_thread.join()

        if self._socket is not None:
            self._socket.close()
            self._socket = None

        self._sender_thread = None
        self._receiver_thread = None

    def get_message(self) -> str | None:
        """Returns received message from queue"""

        try:
            return self._queues.receive.get(block=False)
        except queue.Empty:
            return None

    def get_status_message(self) -> ClientServiceMessages | None:
        """Returns received message from queue"""

        try:
            return self._queues.status.get(block=False)
        except queue.Empty:
            return None

    def send_message(self, message: str):
        """Sends messages to server.

        Args:
            message (str): Message to send to server.
        """
        self._queues.send.put(message)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
