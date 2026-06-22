"""Build the firmware fixture for this demo (stdlib only).

Run from the repo root:  python demos/08-multi-volume/build.py
"""
import os, sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "_lib"))
import fwbuild as fw

_OUT = os.path.join(_HERE, "firmware.bin")


def build():
    return fw.assemble(fw.firmware_volume(body_len=0x800), fw.firmware_volume(body_len=0x800, file_system_guid=bytes(range(16,32))), fw.secureboot_vars(["PK","KEK","db","dbx"]), fw.pe_module(signed=True), fw.pe_module(signed=True))


def main():
    data = build()
    with open(_OUT, "wb") as fh:
        fh.write(data)
    print("wrote {} ({} bytes)".format(_OUT, len(data)))


if __name__ == "__main__":
    main()
