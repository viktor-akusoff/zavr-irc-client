"""Custom exceptions and nothing more"""


class ClientConnectionError(Exception):
    """Some error occured while trying to connect to a server."""

class ClientIsNotConnectedError(Exception):
    """Client isn't connected to any kind of server."""

class ParserReceivedEmptyStringError(ValueError):
    """Parser received an empty string."""

class ParserMalformedCommandError(IndexError):
    """Parser received incorrect command."""