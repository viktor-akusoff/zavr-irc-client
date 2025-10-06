from typing import NamedTuple, Optional, Tuple
import exceptions


class Command(NamedTuple):
    """Single parsed command with its params."""

    prefix: Optional[str] = None
    command: str
    params: Tuple[str]


def str_to_irc_command(line: str) -> Command:
    """Parses a raw IRC message string into a Command object.

    The parsing logic strictly follows the structure defined in RFC 2812.
    Format: [:<prefix>] <command> [<params>]

    Args:
        line: A single, raw IRC message string (without trailing \\r\\n).

    Returns:
        A Command NamedTuple containing the parsed components.

    Raises:
        ParserReceivedEmptyStringError: If the input line is empty.
        ParserReceivedMalformedCommand: If the line is malformed and a command cannot be extracted.
    """

    line = line.strip()

    if not line:
        raise exceptions.ParserReceivedEmptyStringError('Parser received an empty string!')

    prefix = None
    trailing_part = None

    if line.startswith(':'):
        prefix, line = line.split(' ', maxsplit=1)
        prefix = prefix[1:]

    if ' :' in line:
        main_part, trailing_part = line.split(' :', maxsplit=1)
        params = main_part.split()
        params.append(trailing_part)
    else:
        params = line.split()

    if not params:
        raise exceptions.ParserMalformedCommandError('Parser received malformed command!')

    command = params.pop(0)

    return Command(prefix, command, tuple(params))