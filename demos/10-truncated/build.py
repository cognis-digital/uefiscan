"""Build the firmware fixture for this demo (stdlib only).

Run from the repo root:  python demos/10-truncated/build.py
"""
import os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "_lib"))
import fwbuild as fw

_OUT = os.path.join(_HERE, "firmware.bin")


def build():
    return b"MZ" + b"\x00" * 20


def main():
    data = build()
    with open(_OUT, "wb") as fh:
        fh.write(data)
    print("wrote {} ({} bytes)".format(_OUT, len(data)))


if __name__ == "__main__":
    main()
