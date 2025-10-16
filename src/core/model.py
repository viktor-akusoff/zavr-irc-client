from typing import Dict, Any, Set
import datetime
import dataclasses
import enum
import collections

class ServerConnectionStatus(str, enum.Enum):
    CONNECTING = "connecting"
    CONNECTED = "connected"
    ERROR = "error"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"

@dataclasses.dataclass
class Message:
    nickname: str
    timestamp: datetime.datetime
    text: str

@dataclasses.dataclass
class Modes:
    lists: Dict[str, Set[str]] = dataclasses.field(default_factory=dict)
    paramed: Dict[str, str] = dataclasses.field(default_factory=dict)
    flags: Set[str] = dataclasses.field(default_factory=set)

@dataclasses.dataclass
class Channel:
    name: str
    topic: str
    users: Dict[str, Set[str]] = dataclasses.field(default_factory=dict)
    messages: collections.deque[Message] = dataclasses.field(
        default_factory=collections.deque
    )
    modes: Modes = dataclasses.field(default_factory=Modes)

@dataclasses.dataclass
class Query:
    nickname: str
    messages: collections.deque[Message] = dataclasses.field(
        default_factory=collections.deque
    )

@dataclasses.dataclass
class ServerConnection:
    identity: str
    status: ServerConnectionStatus = dataclasses.field(
        default=ServerConnectionStatus.DISCONNECTED
    )
    nickname: str
    capabilities: Dict[str, Any] = dataclasses.field(default_factory=dict)
    channels: Dict[str, Channel] = dataclasses.field(default_factory=dict)
    queries: Dict[str, Query] = dataclasses.field(default_factory=dict)
    service_window: collections.deque[str] = dataclasses.field(
        default_factory=collections.deque
    )

@dataclasses.dataclass
class AppState:
    """Global app state."""
    connections: Dict[str, ServerConnection] = dataclasses.field(default_factory=dict)
