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
        self.data = data
        self.names = names

    def __len__(self):
        return len(self.data) // CALL.size

    def rows(self):
        return CALL.iter_unpack(self.data)

    def targets(self):
        return TARGET.iter_unpack(self.data)

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
        for index in range(count):
            name, = struct.unpack_from("<Q", calls, index * CALL.size + 8)
            if name > name_count:
                raise ValueError("invalid oracle call name")
        record["calls"] = PackedCalls(calls, names)
        result.append(record)
    return result


def record_json(value):
    if isinstance(value, PackedCalls):
        return list(value)
    raise TypeError(f"cannot encode {type(value).__name__}")


def read_records(stream):
    """Map a completed run so multi-million-call traces need no whole-run byte copies."""
    return decode_records(mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
                          if os.fstat(stream.fileno()).st_size else b"")
