"""Behaviour tests for the checksum and framing kernel.

They only look at what a caller can observe: the table the kernel builds, the
check values it produces, the bytes it writes on the wire and the errors it
reports.  Run them from the project root:

    python3 -m unittest discover -s tests -v
"""

import os
import sys
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crc32.core import (
    CHECKSUM_SIZE,
    LENGTH_SIZE,
    MAX_PAYLOAD,
    FrameError,
    crc32,
    crc_table,
    declared_length,
    decode_frame,
    encode_frame,
    locate_bad_frames,
    split_frames,
)


def raw_frame(payload):
    """Build a frame straight from the wire format, checksum included."""
    body = len(payload).to_bytes(LENGTH_SIZE, "big") + payload
    checksum = zlib.crc32(body) & 0xFFFFFFFF
    return body + checksum.to_bytes(CHECKSUM_SIZE, "big")


def payload_of(size):
    """A payload whose bytes are easy to tell apart."""
    return bytes((index * 7 + 1) & 0xFF for index in range(size))


def frame_starts(frames):
    """The offset every frame of a recording starts at."""
    starts = []
    position = 0
    for frame in frames:
        starts.append(position)
        position += len(frame)
    return starts


class KernelTestCase(unittest.TestCase):
    """Helper for calls that are supposed to come back with a value."""

    def succeeds(self, function, *args):
        """Call function and report a raised FrameError as a failure."""
        try:
            return function(*args)
        except FrameError as error:
            self.fail("%s raised %s" % (function.__name__, error))


class TableTestCase(unittest.TestCase):
    """The table is what turns the polynomial into one lookup per byte."""

    def test_the_reflected_table_follows_the_ieee_polynomial(self):
        table = crc_table()
        self.assertEqual(len(table), 256)
        self.assertEqual(table[0], 0x00000000)
        self.assertEqual(table[1], 0x77073096)
        self.assertEqual(table[128], 0xEDB88320)
        self.assertEqual(table[255], 0x2D02EF8D)


class CheckValueTestCase(unittest.TestCase):
    """The check values every CRC-32 implementation has to agree on."""

    def test_the_standard_check_values_are_reproduced(self):
        self.assertEqual(crc32(b""), 0x00000000)
        self.assertEqual(crc32(b"a"), 0xE8B7BE43)
        self.assertEqual(crc32(b"abc"), 0x352441C2)
        self.assertEqual(crc32(b"hello"), 0x3610A686)
        self.assertEqual(crc32(b"123456789"), 0xCBF43926)

    def test_a_checksum_can_be_continued_over_more_bytes(self):
        head, tail = b"1234", b"56789"
        self.assertEqual(crc32(head, 0), crc32(head))
        self.assertEqual(crc32(b"", crc32(head)), crc32(head))
        self.assertEqual(crc32(tail, crc32(head)), crc32(head + tail))
        message = payload_of(1000)
        first = crc32(message[:300])
        second = crc32(message[300:700], first)
        self.assertEqual(crc32(message[700:], second), crc32(message))


class FrameShapeTestCase(KernelTestCase):
    """What the kernel writes has to match the layout it documents."""

    def test_a_small_frame_looks_like_the_wire_format_describes(self):
        raw = encode_frame(b"hello")
        self.assertEqual(len(raw), LENGTH_SIZE + 5 + CHECKSUM_SIZE)
        self.assertEqual(raw[:LENGTH_SIZE], b"\x00\x05")
        self.assertEqual(raw[LENGTH_SIZE:LENGTH_SIZE + 5], b"hello")
        payload, end = self.succeeds(decode_frame, raw)
        self.assertEqual(payload, b"hello")
        self.assertEqual(end, len(raw))
        stored = int.from_bytes(raw[-CHECKSUM_SIZE:], "big")
        self.assertEqual(stored, zlib.crc32(raw[:-CHECKSUM_SIZE]) & 0xFFFFFFFF)
        payload, end = self.succeeds(decode_frame, raw + b"left over")
        self.assertEqual(payload, b"hello")
        self.assertEqual(end, len(raw))

    def test_the_declared_length_tracks_the_payload_at_every_size(self):
        for size in (0, 255, 256, 300, MAX_PAYLOAD):
            payload = payload_of(size)
            raw = encode_frame(payload)
            self.assertEqual(len(raw), LENGTH_SIZE + size + CHECKSUM_SIZE)
            self.assertEqual(declared_length(raw), size, "%d bytes" % size)
            got, end = self.succeeds(decode_frame, raw)
            self.assertEqual(got, payload)
            self.assertEqual(end, len(raw))


class LimitTestCase(KernelTestCase):
    """The frame limits sit on the payload, and the top one is inclusive."""

    def test_a_payload_at_the_limit_still_travels(self):
        payload = payload_of(MAX_PAYLOAD)
        raw = encode_frame(payload)
        self.assertEqual(len(raw), LENGTH_SIZE + MAX_PAYLOAD + CHECKSUM_SIZE)
        self.assertEqual(declared_length(raw), MAX_PAYLOAD)
        got, end = self.succeeds(decode_frame, raw)
        self.assertEqual(got, payload)
        self.assertEqual(end, len(raw))

    def test_a_payload_above_the_limit_is_rejected_on_both_sides(self):
        payload = payload_of(MAX_PAYLOAD + 1)
        with self.assertRaises(FrameError):
            encode_frame(payload)
        raw = raw_frame(payload)
        self.assertEqual(len(raw), LENGTH_SIZE + MAX_PAYLOAD + 1 + CHECKSUM_SIZE)
        with self.assertRaises(FrameError):
            decode_frame(raw)
        with self.assertRaises(FrameError):
            split_frames(raw)


class DamageTestCase(KernelTestCase):
    """Damage has to be reported, and reported where it happened."""

    def test_a_flipped_bit_is_never_accepted(self):
        raw = encode_frame(b"payload")
        for position in range(len(raw)):
            damaged = raw[:position] + bytes([raw[position] ^ 0x40]) + raw[position + 1:]
            with self.assertRaises(FrameError):
                decode_frame(damaged)

    def test_a_recording_reports_every_damaged_frame(self):
        sizes = (3, 5, 2048, 7)
        frames = [encode_frame(payload_of(size)) for size in sizes]
        starts = frame_starts(frames)
        recording = b"".join(frames)
        self.assertEqual(self.succeeds(locate_bad_frames, recording), [])
        self.assertEqual(
            self.succeeds(split_frames, recording),
            [payload_of(size) for size in sizes],
        )
        damaged = list(frames)
        damaged[1] = damaged[1][:-1] + bytes([damaged[1][-1] ^ 0x01])
        damaged[3] = (
            damaged[3][:-CHECKSUM_SIZE]
            + bytes([damaged[3][-CHECKSUM_SIZE] ^ 0x80])
            + damaged[3][-CHECKSUM_SIZE + 1:]
        )
        self.assertEqual(
            self.succeeds(locate_bad_frames, b"".join(damaged)),
            [starts[1], starts[3]],
        )
        with self.assertRaises(FrameError) as caught:
            split_frames(b"".join(damaged))
        self.assertEqual(caught.exception.offset, starts[1])

    def test_a_truncated_tail_is_reported_at_the_partial_frame(self):
        empty = encode_frame(b"")
        with self.assertRaises(FrameError) as caught:
            split_frames(empty + empty[:3])
        self.assertEqual(caught.exception.offset, len(empty))
        with self.assertRaises(FrameError) as caught:
            split_frames(empty + b"\x00")
        self.assertEqual(caught.exception.offset, len(empty))
        first = encode_frame(b"one")
        second = encode_frame(b"second")
        self.assertEqual(
            self.succeeds(split_frames, first + second),
            [b"one", b"second"],
        )
        with self.assertRaises(FrameError) as caught:
            split_frames(first + second[:LENGTH_SIZE + 2])
        self.assertEqual(caught.exception.offset, len(first))


if __name__ == "__main__":
    unittest.main()
