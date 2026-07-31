# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.


import struct
import zipfile
from pathlib import Path
from dextrace.core.apk_reader import ApkReader

_BOGUS_COMPRESSION = 8744  # invalid ZIP compression type used as anti-analysis trick


def _make_zip_with_bogus_compression(tmp_path: Path, filename: str, content: bytes) -> str:
    """Write a ZIP file then patch both CDH and LFH compression method to 8744.

    Python's zipfile raises NotImplementedError when it encounters an unknown
    compression type. This helper creates the same byte layout that malware APKs
    like 3d52b5728... use to foil static analysis tools.
    """
    apk_path = tmp_path / "bogus.apk"
    with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_STORED) as z:
        z.writestr(filename, content)

    raw = bytearray(apk_path.read_bytes())

    lfh_off = raw.find(b"PK\x03\x04")
    if lfh_off != -1:
        struct.pack_into("<H", raw, lfh_off + 8, _BOGUS_COMPRESSION)

    cdh_off = raw.find(b"PK\x01\x02")
    if cdh_off != -1:
        struct.pack_into("<H", raw, cdh_off + 10, _BOGUS_COMPRESSION)

    apk_path.write_bytes(bytes(raw))
    return str(apk_path)


def test_apk_reader_lists_entries(tmp_path: Path):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("classes.dex", b"hello")
        z.writestr("AndroidManifest.xml", b"<manifest/>")

    reader = ApkReader(str(apk_path))
    entries = reader.list_entries()

    assert "classes.dex" in entries
    assert "AndroidManifest.xml" in entries


def test_apk_reader_extracts_file(tmp_path: Path):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("test.txt", b"abcdef")

    reader = ApkReader(str(apk_path))
    content = reader.read_file("test.txt")

    assert content == b"abcdef"


def test_apk_reader_iter_dex_files(tmp_path: Path):
    apk_path = tmp_path / "fake.apk"
    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("classes.dex", b"dexcontent")
        z.writestr("notdex.txt", b"nope")

    reader = ApkReader(str(apk_path))
    dex_files = reader.iter_dex_files()

    assert len(dex_files) == 1
    name, data = dex_files[0]
    assert name == "classes.dex"
    assert data == b"dexcontent"


def test_apk_reader_bogus_compression_does_not_raise(tmp_path: Path):
    """ApkReader must open a ZIP with a bogus compression type without raising.

    Malware APKs set the compression method to an invalid value (e.g. 8744)
    while storing data uncompressed. Python's zipfile raises NotImplementedError
    for unknown compression types. _patch_apk() must fix this before opening.
    """
    apk_path = _make_zip_with_bogus_compression(tmp_path, "AndroidManifest.xml", b"\x03\x00\x08\x00")
    # Must not raise NotImplementedError
    reader = ApkReader(apk_path)
    assert "AndroidManifest.xml" in reader.list_entries()


def test_apk_reader_bogus_compression_content_intact(tmp_path: Path):
    """File content must survive the compression method patch unchanged."""
    payload = b"hello from bogus zip"
    apk_path = _make_zip_with_bogus_compression(tmp_path, "test.txt", payload)
    reader = ApkReader(apk_path)
    assert reader.read_file("test.txt") == payload


def test_apk_reader_normal_zip_unaffected(tmp_path: Path):
    """_patch_apk must not corrupt a well-formed ZIP (STORED or DEFLATE entries)."""
    apk_path = tmp_path / "normal.apk"
    with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("classes.dex", b"A" * 256)

    reader = ApkReader(str(apk_path))
    assert reader.read_file("classes.dex") == b"A" * 256
