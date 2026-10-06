"""crc32: a reflected CRC-32 checksum with a length prefixed frame kernel."""

from .core import (
    CHECKSUM_SIZE,
    INIT,
    LENGTH_SIZE,
    MAX_FRAME_SIZE,
    MAX_PAYLOAD,
    MIN_FRAME_SIZE,
    POLY,
    XOROUT,
    FrameError,
    crc32,
    crc_table,
    declared_length,
    decode_frame,
    encode_frame,
    locate_bad_frames,
    split_frames,
)

__all__ = [
    "CHECKSUM_SIZE",
    "INIT",
    "LENGTH_SIZE",
    "MAX_FRAME_SIZE",
    "MAX_PAYLOAD",
    "MIN_FRAME_SIZE",
    "POLY",
    "XOROUT",
    "FrameError",
    "crc32",
    "crc_table",
    "declared_length",
    "decode_frame",
    "encode_frame",
    "locate_bad_frames",
    "split_frames",
]
