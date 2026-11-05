"""Builds small synthetic PE files for tests. Their code section is NOPs, so they do nothing."""

import random
import struct
import time

FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
READ, WRITE, EXEC, CODE, IDATA = 0x40000000, 0x80000000, 0x20000000, 0x20, 0x40


def _align(value: int, boundary: int) -> int:
    return (value + boundary - 1) // boundary * boundary


def _build_idata(imports: dict[str, list[str]], rva: int) -> bytes:
    descriptors_size = 20 * (len(imports) + 1)
    blob = bytearray(descriptors_size)
    descriptors = []
    for dll, functions in imports.items():
        name_rva = rva + len(blob)
        blob += dll.encode() + b"\0"
        hint_rvas = []
        for function in functions:
            hint_rvas.append(rva + len(blob))
            blob += b"\0\0" + function.encode() + b"\0"
            if len(blob) % 2:
                blob += b"\0"
        table = b"".join(struct.pack("<I", value) for value in hint_rvas) + b"\0\0\0\0"
        lookup_rva = rva + len(blob)
        blob += table
        address_rva = rva + len(blob)
        blob += table
        descriptors.append(struct.pack("<IIIII", lookup_rva, 0, 0, name_rva, address_rva))
    blob[: 20 * len(descriptors)] = b"".join(descriptors)
    return bytes(blob)


def build_pe(imports: dict[str, list[str]], extra_strings: list[str] | None = None, packed: bool = False, timestamp: int | None = None) -> bytes:
    text = b"\x90" * 0x200
    data = b"\0".join(s.encode("ascii") for s in (extra_strings or [])) + b"\0"

    sections: list[tuple[bytes, bytes, int, int]] = [
        (b".text", text, 0x200, CODE | READ | EXEC),
        (b".rdata", data, len(data), IDATA | READ),
    ]
    if packed:
        rng = random.Random(1337)  # noqa: S311
        noise = bytes(rng.randrange(256) for _ in range(0x4000))
        sections = [
            (b"UPX0", b"", 0x8000, CODE | READ | WRITE | EXEC),
            (b"UPX1", noise + data, len(noise) + len(data), CODE | READ | WRITE | EXEC),
        ]

    headers_size = _align(0x40 + 4 + 20 + 224 + 40 * (len(sections) + 1), FILE_ALIGN)
    rva = SECTION_ALIGN
    raw = headers_size
    table = b""
    bodies = b""
    entry_rva = 0
    for index, (name, body, virtual_size, flags) in enumerate(sections):
        padded = body + b"\0" * (_align(len(body), FILE_ALIGN) - len(body)) if body else b""
        table += struct.pack("<8sIIIIIIHHI", name, virtual_size, rva, len(padded), raw if body else 0, 0, 0, 0, 0, flags)
        bodies += padded
        if index == len(sections) - 1 or name == b".text":
            entry_rva = entry_rva or rva
        raw += len(padded)
        rva += _align(max(virtual_size, 1), SECTION_ALIGN)

    idata_rva = rva
    idata = _build_idata(imports, idata_rva)
    padded = idata + b"\0" * (_align(len(idata), FILE_ALIGN) - len(idata))
    table += struct.pack("<8sIIIIIIHHI", b".idata", len(idata), rva, len(padded), raw, 0, 0, 0, 0, IDATA | READ | WRITE)
    bodies += padded
    image_size = rva + _align(len(idata), SECTION_ALIGN)

    dos = b"MZ" + b"\0" * 58 + struct.pack("<I", 0x40)
    stamp = int(time.time()) - 86400 if timestamp is None else timestamp
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x14C, len(sections) + 1, stamp, 0, 0, 224, 0x0102)
    optional = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x10B, 14, 0, 0x200, 0x200, 0, entry_rva, SECTION_ALIGN, SECTION_ALIGN, 0x400000, SECTION_ALIGN, FILE_ALIGN,
        6, 0, 0, 0, 6, 0, 0, image_size, headers_size, 0, 3, 0x8140, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16,
    )
    directories = bytearray(8 * 16)
    directories[8:16] = struct.pack("<II", idata_rva, len(idata))
    header = dos + coff + optional + bytes(directories) + table
    return header + b"\0" * (headers_size - len(header)) + bodies
