"""Shared offline firmware-image fixtures for the test suite.

Re-uses the demo's standard-library builder so tests never need real firmware.
"""
import importlib.util
import os

_DEMO_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic")
)


def load_builder():
    path = os.path.join(_DEMO_DIR, "make_sample.py")
    spec = importlib.util.spec_from_file_location("make_sample_fix", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def sample_failing():
    """One FV, PK/KEK/db (no dbx), one signed + one unsigned PE -> FAIL."""
    m = load_builder()
    return b"".join([
        m.build_firmware_volume(),
        m.build_variables(),
        m.build_pe(signed=True),
        b"\xff" * 0x40,
        m.build_pe(signed=False),
    ])


def sample_clean():
    """One FV, PK/KEK/db + dbx, one signed PE -> PASS."""
    m = load_builder()
    return b"".join([
        m.build_firmware_volume(),
        m.build_variables() + "dbx".encode("utf-16-le") + b"\x00\x00",
        m.build_pe(signed=True),
    ])
