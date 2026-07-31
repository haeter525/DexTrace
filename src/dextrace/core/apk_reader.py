# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

"""
Low-level APK reader.

Responsible only for:
- opening the APK as a ZIP archive
- listing entries
- reading raw file contents
"""

import io
import os
import struct
import zlib
import zipfile
from typing import List, Tuple

_EOCD_SIG = b"PK\x05\x06"
_CDH_SIG = b"PK\x01\x02"
_LFH_SIG = b"PK\x03\x04"
# Only STORED (0) and DEFLATE (8) are universally supported by Python's zipfile.
_SUPPORTED_METHODS = frozenset({0, 8})
_MANIFEST_NAME = b"AndroidManifest.xml"


def _iter_cdh(data: bytearray, cdh_count: int, cdh_start: int):
    """Yield (offset, fname_len, extra_len, comment_len) for each CDH entry."""
    offset = cdh_start
    for _ in range(cdh_count):
        if data[offset : offset + 4] != _CDH_SIG:
            break
        (fname_len,) = struct.unpack_from("<H", data, offset + 28)
        (extra_len,) = struct.unpack_from("<H", data, offset + 30)
        (comment_len,) = struct.unpack_from("<H", data, offset + 32)
        yield offset, fname_len, extra_len, comment_len
        offset += 46 + fname_len + extra_len + comment_len


def _patch_apk(data: bytearray) -> None:
    """Patch two anti-analysis tricks used in some malware APKs.

    1. Invalid compression method (e.g. 8744) on stored entries — Python's
       zipfile raises NotImplementedError; reset to STORED (0).
    2. Corrupted AXML magic byte in AndroidManifest.xml — first byte must be
       0x03 for Androguard/axmlparserpy to parse the binary XML.
    """
    eocd_offset = data.rfind(_EOCD_SIG)
    if eocd_offset == -1:
        return

    (cdh_count,) = struct.unpack_from("<H", data, eocd_offset + 10)
    (cdh_start,) = struct.unpack_from("<I", data, eocd_offset + 16)

    for offset, fname_len, extra_len, comment_len in _iter_cdh(data, cdh_count, cdh_start):
        (method,) = struct.unpack_from("<H", data, offset + 10)
        (uncompressed_size,) = struct.unpack_from("<I", data, offset + 24)
        (lfh_offset,) = struct.unpack_from("<I", data, offset + 42)

        if method not in _SUPPORTED_METHODS:
            struct.pack_into("<H", data, offset + 10, 0)
            struct.pack_into("<I", data, offset + 20, uncompressed_size)
            if data[lfh_offset : lfh_offset + 4] == _LFH_SIG:
                struct.pack_into("<H", data, lfh_offset + 8, 0)
                struct.pack_into("<I", data, lfh_offset + 18, uncompressed_size)

        # Patch AXML magic byte in manifest (must be 0x03 after compression fix)
        fname_start = offset + 46
        if data[fname_start : fname_start + len(_MANIFEST_NAME)] != _MANIFEST_NAME:
            continue

        (effective_method,) = struct.unpack_from("<H", data, offset + 10)
        if effective_method != 0:
            continue  # only patch STORED manifests

        if data[lfh_offset : lfh_offset + 4] != _LFH_SIG:
            continue

        (lfh_fname_len,) = struct.unpack_from("<H", data, lfh_offset + 26)
        (lfh_extra_len,) = struct.unpack_from("<H", data, lfh_offset + 28)
        data_offset = lfh_offset + 30 + lfh_fname_len + lfh_extra_len

        if uncompressed_size == 0 or data[data_offset] == 0x03:
            continue

        data[data_offset] = 0x03
        new_crc = zlib.crc32(data[data_offset : data_offset + uncompressed_size]) & 0xFFFFFFFF
        struct.pack_into("<I", data, offset + 16, new_crc)
        struct.pack_into("<I", data, lfh_offset + 14, new_crc)


class ApkReader:
    """Low-level reader for APK files. No parsing logic is implemented here."""

    def __init__(self, apk_path: str):
        if not os.path.isfile(apk_path):
            raise FileNotFoundError(f"APK not found: {apk_path}")
        self.apk_path = apk_path
        with open(apk_path, "rb") as f:
            raw = bytearray(f.read())
        _patch_apk(raw)
        self._zip = zipfile.ZipFile(io.BytesIO(raw), "r")

    def list_entries(self) -> List[str]:
        """Return the list of entries inside the APK."""
        return self._zip.namelist()

    def read_file(self, name: str) -> bytes:
        """Read a file from the APK by name and return its raw bytes."""
        with self._zip.open(name) as f:
            return f.read()

    def iter_dex_files(self) -> list[Tuple[str, bytes]]:
        """Return a list of (filename, raw_bytes) for all *.dex entries."""
        return [
            (name, self.read_file(name))
            for name in sorted(self.list_entries())
            if name.endswith(".dex")
        ]
