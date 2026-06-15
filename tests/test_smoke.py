"""Smoke tests for UEFISCAN: import core, build the demo image, audit it."""

import importlib.util
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from uefiscan import core, TOOL_NAME, TOOL_VERSION
from uefiscan.cli import main

_DEMO_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic")
)


def _load_sample_builder():
    path = os.path.join(_DEMO_DIR, "make_sample.py")
    spec = importlib.util.spec_from_file_location("make_sample", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build_sample():
    mod = _load_sample_builder()
    return b"".join(
        [
            mod.build_firmware_volume(),
            mod.build_variables(),
            mod.build_pe(signed=True),
            b"\xff" * 0x40,
            mod.build_pe(signed=False),
        ]
    )


def test_metadata():
    assert TOOL_NAME == "uefiscan"
    assert TOOL_VERSION.count(".") == 2


def test_firmware_volume_detected():
    data = _build_sample()
    fvs = core.find_firmware_volumes(data)
    assert len(fvs) == 1
    assert fvs[0] == 0  # FV is first in the image


def test_fv_checksum_rejects_garbage():
    # "_FVH" present but no valid header checksum -> not counted.
    junk = b"\x00" * 40 + b"_FVH" + b"\x00" * 40
    assert core.find_firmware_volumes(junk) == []


def test_secureboot_vars():
    data = _build_sample()
    sb = core.find_efi_variables(data)
    assert sb["PK"] is True
    assert sb["KEK"] is True
    assert sb["db"] is True
    assert sb["dbx"] is False  # demo omits dbx


def test_module_signature_detection():
    data = _build_sample()
    mods = core.find_pe_modules(data)
    assert len(mods) == 2
    assert sum(1 for m in mods if m.signed) == 1
    assert sum(1 for m in mods if not m.signed) == 1


def test_audit_fails_on_unsigned_module():
    data = _build_sample()
    result = core.audit_bytes(data, path="sample")
    assert result.verdict == "FAIL"
    assert result.ok is False
    codes = {f.code for f in result.findings}
    assert "unsigned-modules" in codes
    assert "no-dbx" in codes  # warning for missing revocation list
    d = result.to_dict()
    assert d["modules"]["unsigned"] == 1
    assert d["firmware_volumes"] == 1


def test_clean_image_passes():
    mod = _load_sample_builder()
    clean = b"".join(
        [
            mod.build_firmware_volume(),
            mod.build_variables() + "dbx".encode("utf-16-le") + b"\x00\x00",
            mod.build_pe(signed=True),
        ]
    )
    result = core.audit_bytes(clean, path="clean")
    assert result.secureboot_vars["dbx"] is True
    assert result.unsigned_modules == 0
    assert result.verdict == "PASS"
    assert result.ok is True


def test_too_small_image():
    result = core.audit_bytes(b"MZ", path="tiny")
    assert result.verdict == "FAIL"
    assert any(f.code == "too-small" for f in result.findings)


def test_cli_json_and_exit_code(tmp_path, capsys):
    sample = _build_sample()
    p = tmp_path / "fw.bin"
    p.write_bytes(sample)
    rc = main(["scan", str(p), "--format", "json"])
    assert rc == 1  # FAIL -> non-zero for CI gating
    out = capsys.readouterr().out
    assert '"verdict": "FAIL"' in out
    assert '"tool": "uefiscan"' in out


def test_cli_missing_file():
    rc = main(["scan", "does-not-exist-xyz.bin"])
    assert rc == 2

# ---------------------------------------------------------------------------
# Hardening tests (input validation, error paths, edge cases)
# ---------------------------------------------------------------------------


def test_audit_bytes_rejects_non_bytes():
    """audit_bytes must raise TypeError for non-bytes input."""
    import pytest
    with pytest.raises(TypeError, match="audit_bytes"):
        core.audit_bytes("not bytes", path="x")


def test_audit_bytes_accepts_bytearray():
    """audit_bytes should accept bytearray and treat it as bytes."""
    result = core.audit_bytes(bytearray(b"MZ"), path="ba")
    assert result.verdict == "FAIL"
    assert any(f.code == "too-small" for f in result.findings)


def test_audit_bytes_empty_input():
    """Empty bytes should fail gracefully with too-small finding."""
    result = core.audit_bytes(b"", path="empty")
    assert result.verdict == "FAIL"
    assert any(f.code == "too-small" for f in result.findings)


def test_audit_bytes_all_zeros():
    """All-zero image: no FV, no keys, no modules - must not raise."""
    result = core.audit_bytes(bytes(512), path="zeros")
    assert result.verdict == "FAIL"
    codes = {f.code for f in result.findings}
    assert "no-firmware-volume" in codes
    assert "missing-secureboot-keys" in codes


def test_cli_no_subcommand(capsys):
    """Calling the CLI with no subcommand should print help and exit 2."""
    rc = main([])
    assert rc == 2


def test_cli_empty_file(tmp_path, capsys):
    """A zero-byte file should return a non-zero exit and a clear FAIL."""
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    rc = main(["scan", str(p)])
    assert rc == 1  # audit FAIL -> exit 1
    out = capsys.readouterr().out
    assert "FAIL" in out


def test_mcp_server_imports():
    """mcp_server must import without error (broken scan/to_json import is fixed)."""
    import importlib
    mod = importlib.import_module("uefiscan.mcp_server")
    assert callable(mod.serve)


def test_pe_truncated_header():
    """Truncated PE header must not raise - _check_pe_signed returns None."""
    import struct
    # DOS header where e_lfanew points way past end-of-buffer
    data = bytearray(0x40)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0xFFFF0000)
    mods = core.find_pe_modules(bytes(data))
    assert mods == []
