"""Checksum and framing kernel for length prefixed records.

Everything here is done with integers and bytes and stays in memory: the
kernel never reads a file, never looks at a clock and never uses a random
source, so the same call always returns the same answer.

A frame is laid out like this::

    +--------------+-----------+------------------+
    | length (2 B) | payload   | checksum (4 B)   |
    | big endian   | N bytes   | big endian       |
    +--------------+-----------+------------------+

The length field counts the payload bytes that follow it, so the smallest
frame carries six bytes and an empty payload is legal.  The checksum is the
reflected CRC-32 of the length field together with the payload: polynomial
0xEDB88320, register preset to 0xFFFFFFFF, final value xored with
0xFFFFFFFF.

``crc32`` keeps the usual continuation convention: the value returned for an
earlier chunk can be passed back in to carry the checksum on, so a sender may
fold a stream in pieces and still agree with a single whole pass.
"""

#: The CRC-32 polynomial in its reflected form.
POLY = 0xEDB88320

#: Value the register is preset to before the first byte.
INIT = 0xFFFFFFFF

#: Value the register is xored with once the last byte is folded in.
XOROUT = 0xFFFFFFFF

#: Width of the register.
MASK = 0xFFFFFFFF

#: Size of the length field in front of a payload.
LENGTH_SIZE = 2

#: Size of the checksum field behind a payload.
CHECKSUM_SIZE = 4

#: Largest payload a single frame may carry, in bytes.
MAX_PAYLOAD = 4096

#: Smallest number of bytes a frame may occupy on the wire.
MIN_FRAME_SIZE = LENGTH_SIZE + CHECKSUM_SIZE

#: Largest number of bytes a frame may occupy on the wire.
MAX_FRAME_SIZE = LENGTH_SIZE + MAX_PAYLOAD + CHECKSUM_SIZE

#: The lookup table, built on first use.
_TABLE = None


class FrameError(Exception):
    """Reported when a buffer is not a well formed frame.

    ``offset`` says where the trouble starts: the first byte of the frame for
    a frame that is damaged or too large, and the first byte of the partial
    frame for a buffer that stops before a frame is complete.
    """

    def __init__(self, message, offset=None):
        super().__init__(message)
        self.message = message
        self.offset = offset


# ---------------------------------------------------------------------------
# Checksum
# ---------------------------------------------------------------------------

def crc_table():
    """Return the 256 entry lookup table of the reflected polynomial.

    The table is built once and handed out as a tuple, so callers may keep it
    around and folding a byte costs a single lookup.
    """
    global _TABLE
    if _TABLE is None:
        rows = []
        for index in range(256):
            register = index
            for _ in range(8):
                if register & 1:
                    register = (register >> 1) ^ POLY
                else:
                    register >>= 1
            rows.append(register & MASK)
        _TABLE = tuple(rows)
    return _TABLE


def crc32(data, crc=0):
    """Return the CRC-32 of ``data``, continuing from the value ``crc``.

    Passing back the value of an earlier call keeps the checksum running, so
    ``crc32(tail, crc32(head))`` and ``crc32(head + tail)`` agree.
    """
    value = crc ^ INIT
    table = crc_table()
    for byte in data:
        value = table[(value ^ byte) & 0xFF] ^ (value >> 8)
    return value ^ XOROUT


# ---------------------------------------------------------------------------
# Frames
# ---------------------------------------------------------------------------

def declared_length(data, offset=0):
    """Return the payload length written in the frame at ``offset``."""
    if len(data) - offset < LENGTH_SIZE:
        raise FrameError("the length field is truncated", offset)
    return int.from_bytes(data[offset:offset + LENGTH_SIZE], "big")


def _frame_span(data, offset):
    """Return ``(body_end, frame_end)`` for the frame that starts at ``offset``.

    ``body_end`` is where the checksum field begins and ``frame_end`` is the
    byte just past the frame.  Raises :class:`FrameError` when the declared
    length is outside the kernel limits or when the buffer stops before the
    frame is complete.
    """
    length = declared_length(data, offset)
    if length > MAX_PAYLOAD:
        raise FrameError("the payload is larger than the kernel allows", offset)
    frame_end = offset + LENGTH_SIZE + length + CHECKSUM_SIZE
    if frame_end > len(data):
        raise FrameError("the frame is truncated", offset)
    return frame_end - CHECKSUM_SIZE, frame_end


def _frame_checksum(data, start, body_end):
    """Return the checksum a frame body should carry."""
    return crc32(data[start:body_end])


def encode_frame(payload):
    """Return the frame that carries ``payload``.

    Raises :class:`FrameError` when the payload does not fit in a frame.
    """
    if len(payload) > MAX_PAYLOAD:
        raise FrameError("the payload is larger than the kernel allows")
    body = len(payload).to_bytes(LENGTH_SIZE, "big") + payload
    return body + crc32(body).to_bytes(CHECKSUM_SIZE, "big")


def decode_frame(data, offset=0):
    """Return ``(payload, end)`` for the frame that starts at ``offset``.

    The payload is the bytes between the length field and the checksum field,
    and ``end`` is the byte just past the frame, so a caller can walk a
    buffer frame by frame.  Anything that does not decode is reported through
    :class:`FrameError` and never returned as a half frame.
    """
    if offset < 0 or offset > len(data):
        raise FrameError("the offset is outside the buffer", offset)
    body_end, frame_end = _frame_span(data, offset)
    stored = int.from_bytes(data[body_end:frame_end], "big")
    if stored != _frame_checksum(data, offset, body_end):
        raise FrameError("the checksum does not match", offset)
    return data[offset + LENGTH_SIZE:body_end], frame_end


def split_frames(buffer, offset=0):
    """Return every payload between ``offset`` and the end of ``buffer``.

    A frame whose checksum does not match and a buffer that stops in the
    middle of a frame are both reported through :class:`FrameError`, so no
    bytes are ever dropped without a word.
    """
    payloads = []
    end = len(buffer)
    while offset < end:
        payload, offset = decode_frame(buffer, offset)
        payloads.append(payload)
    return payloads


def locate_bad_frames(buffer, offset=0):
    """Return the offset of every frame whose checksum does not match.

    Intact frames are skipped and the walk carries on past a damaged frame,
    so a whole recording can be checked in one pass.  A buffer that stops in
    the middle of a frame raises :class:`FrameError` with the offset of that
    partial frame.
    """
    damaged = []
    end = len(buffer)
    while offset < end:
        body_end, frame_end = _frame_span(buffer, offset)
        stored = int.from_bytes(buffer[body_end:frame_end], "big")
        if stored != _frame_checksum(buffer, offset, body_end):
            damaged.append(offset)
        offset = frame_end
    return damaged
