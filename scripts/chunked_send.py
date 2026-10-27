#!/usr/bin/env python3
"""Send a raw multipart body with chunked transfer-encoding.

usage:
  python3 chunked_send.py --port 18110 --body-file /tmp/body.bin [--chunk 65536]
"""
from __future__ import annotations

import argparse
import socket
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="/index.php")
    ap.add_argument("--body-file", required=True)
    ap.add_argument("--boundary", default="C" * 10)
    ap.add_argument("--chunk", type=int, default=65536)
    ap.add_argument("--timeout", type=float, default=120.0)
    ap.add_argument("--save-response", default="")
    args = ap.parse_args()

    with open(args.body_file, "rb") as fh:
        body = fh.read()

    hdr = ("POST %s HTTP/1.1\r\nHost: %s:%d\r\n"
           "Content-Type: multipart/form-data; boundary=%s\r\n"
           "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n" %
           (args.path, args.host, args.port, args.boundary)).encode()
    out = bytearray(hdr)
    for i in range(0, len(body), args.chunk):
        piece = body[i:i + args.chunk]
        out += ("%x\r\n" % len(piece)).encode() + piece + b"\r\n"
    out += b"0\r\n\r\n"

    resp = bytearray()
    try:
        s = socket.create_connection((args.host, args.port), timeout=args.timeout)
        s.settimeout(args.timeout)
        try:
            s.sendall(out)
            while len(resp) < 4 << 20:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp.extend(chunk)
        except OSError:
            pass
        s.close()
    except OSError as exc:
        print("connect_error %r" % (exc,), file=sys.stderr)
        return 2

    if args.save_response:
        with open(args.save_response, "wb") as fh:
            fh.write(bytes(resp))
    status = bytes(resp).split(b"\r\n", 1)[0][:60].decode("latin1", "replace")
    print("body=%d resp=%d status=%r" % (len(body), len(resp), status))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
