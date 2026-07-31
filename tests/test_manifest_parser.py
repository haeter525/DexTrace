# -*- coding: utf-8 -*-
# This file is part of DexTrace - https://github.com/ev-flow/DexTrace
# See the file 'LICENSE' for copying permission.

import mmap
import struct
import zipfile
from pathlib import Path

import pytest

from dextrace.core.manifest_parser import ManifestParser
from dextrace.manifest.axml_parser import _ANDROID_RES_ATTR_NAMES, AxmlReader


def test_manifest_parser_returns_error_on_invalid_axml():
    result = ManifestParser.parse(b"not-axml")

    assert "error" in result
    assert result["error"] == "Bad AXML format"


# ---------------------------------------------------------------------------
# Resource ID fallback table
# ---------------------------------------------------------------------------

class TestAndroidResAttrNames:
    """The fallback table must contain the entries critical for manifest parsing."""

    def test_android_name_0x01010003_present(self):
        assert _ANDROID_RES_ATTR_NAMES[0x01010003] == "name"

    def test_android_name_0x0101021b_present(self):
        assert _ANDROID_RES_ATTR_NAMES[0x0101021b] == "name"

    def test_no_false_entries(self):
        """All values must be non-empty strings."""
        for res_id, attr_name in _ANDROID_RES_ATTR_NAMES.items():
            assert isinstance(attr_name, str) and attr_name, (
                f"Blank or non-string value for res_id 0x{res_id:08x}"
            )


# ---------------------------------------------------------------------------
# Resource ID fallback in AxmlReader — integration test with real malware APK
# ---------------------------------------------------------------------------

_MALWARE_APK = (
    "/workspaces/apk-samples/malware-samples/"
    "3d52b5728af55c37d5bd74c3f9b7e9ea6b007a9ec202a648ce3dc7e37ff49b29.apk"
)


@pytest.fixture(scope="module")
def patched_manifest_bytes():
    """Read and patch the manifest from the anti-analysis APK.

    Applies the same ZIP compression fix that ApkReader._patch_apk() does so
    the manifest is extractable, then returns the raw AXML bytes.
    """
    from dextrace.core.apk_reader import _patch_apk

    with open(_MALWARE_APK, "rb") as f:
        raw = bytearray(f.read())
    _patch_apk(raw)
    import io
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        return z.read("AndroidManifest.xml")


@pytest.mark.skipif(
    not Path(_MALWARE_APK).is_file(),
    reason="malware sample not present locally",
)
class TestAxmlReaderResourceIdFallback:
    """AxmlReader must resolve android:name via the resource ID table when the
    string pool entry for the attribute name is blank (anti-analysis trick)."""

    def test_manifest_magic_correct(self, patched_manifest_bytes):
        assert patched_manifest_bytes[:4] == b"\x03\x00\x08\x00"

    def test_permissions_non_empty(self, patched_manifest_bytes):
        result = ManifestParser.parse(patched_manifest_bytes)
        assert len(result["permissions"]) > 0, (
            "permissions is empty — resource ID fallback not working"
        )

    def test_internet_permission_present(self, patched_manifest_bytes):
        result = ManifestParser.parse(patched_manifest_bytes)
        assert "android.permission.INTERNET" in result["permissions"]

    def test_axml_reader_name_attribute_not_question_mark(self, patched_manifest_bytes):
        """uses-permission elements must not have their name under key '?'."""
        with AxmlReader(patched_manifest_bytes) as ax:
            root = ax.get_xml_tree()
        for el in root.findall("uses-permission"):
            assert "?" not in el.attrib or el.attrib.get("name"), (
                "uses-permission/@name resolved to '?' — resource ID fallback failed"
            )
