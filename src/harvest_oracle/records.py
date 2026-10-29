"""Lazy call traces from the harness's versioned binary frames."""

import json
import mmap
import os
import struct
from collections.abc import Sequence


HEADER = struct.Struct("<4Q")
CALL = struct.Struct("<18Q192s")
TARGET = struct.Struct("<QQ320x")
MAGIC = int.from_bytes(b"ORCALL01", "little")


class PackedCalls(Sequence):
    def __init__(self, data, names):
        self.data = memoryview(data)
        self.names = names

    def __len__(self):
        return len(self.data) // CALL.size

    def rows(self):
        return CALL.iter_unpack(self.data)

    def targets(self):
        return TARGET.iter_unpack(self.data)

    def equal_capture_prefix(self, other):
        """Sufficient raw equality of every captured field except the instruction's return site."""
        if self.names != other.names:
            return False
        size = min(len(self.data), len(other.data))
        a, b = self.data[:size].cast("Q"), other.data[:size].cast("Q")
        stride = CALL.size // 8
        return all(a[column::stride] == b[column::stride] for column in range(stride) if column != 17)

    def addresses(self, count):
        """Distinct targets and integer arguments of a prefix, for translation checks."""
        words = self.data[:count * CALL.size].cast("Q")
        stride = CALL.size // 8
        return {value for column in (0, 2, 3, 4, 5, 6, 7) for value in set(words[column::stride])}

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        row = CALL.unpack_from(self.data, index * CALL.size)
        return {"site": hex(row[17]), "to": self.names[row[1] - 1] + "@" + hex(row[0]) if row[1] else hex(row[0]),
                "gp": [hex(n) for n in row[2:8]], "xmm": [hex(n) for n in row[8:16]],
                "deref": [row[18][i * 32:(i + 1) * 32].hex() if row[16] & (1 << i) else "" for i in range(6)]}

    def __eq__(self, other):
        if isinstance(other, PackedCalls) and self.names == other.names and self.data == other.data:
            return True
        return isinstance(other, Sequence) and len(self) == len(other) and all(a == b for a, b in zip(self, other))


class RunRecords(list):
    def __init__(self, data):
        super().__init__()
        self.data = data


def decode_records(data):
    """Decode metadata while keeping calls in their fixed-width wire representation."""
    result = RunRecords(data)
    view = memoryview(data)
    offset = 0

    def take(size):
        nonlocal offset
        if offset + size > len(view):
            raise ValueError("truncated oracle record")
        start = offset
        offset += size
        return view[start:offset]

    while offset < len(view):
        magic, size, count, name_count = HEADER.unpack(take(HEADER.size))
        if magic != MAGIC or size > (1 << 22) + 256 or count > 4096 or name_count > count:
            raise ValueError("invalid oracle record header")
        record = json.loads(take(size).tobytes())
        calls = take(count * CALL.size)
        names = []
        for _ in range(name_count):
            length, = struct.unpack("<Q", take(8))
            names.append(take(length).tobytes().decode())
        # Validate name indices even when no consumer materializes the calls.
        if max(calls.cast("Q")[1::CALL.size // 8], default=0) > name_count:
            raise ValueError("invalid oracle call name")
        record["calls"] = PackedCalls(calls, names)
        result.append(record)
    return result


def record_json(value):
    if isinstance(value, PackedCalls):
        return list(value)
    raise TypeError(f"cannot encode {type(value).__name__}")


def read_records(stream):
    """Map a completed run so multi-million-call traces need no whole-run byte copies.

    Decoded calls keep views into the map, so the map lives as long as the records. A map that kept its own
    descriptor would leak one per run, and a comparison holding thousands of single-seed reruns would exhaust
    the process's open-file limit; Python 3.13's untracked maps keep none, and older versions read the run."""
    fd = stream.fileno()
    size = os.fstat(fd).st_size
    if not size:
        return decode_records(b"")
    try:
        data = mmap.mmap(fd, 0, access=mmap.ACCESS_READ, trackfd=False)
    except TypeError:
        data = os.pread(fd, size, 0)
    return decode_records(data)
