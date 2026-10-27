#!/usr/bin/env python3
import sys, urllib.parse, struct
from collections import Counter
raw = open(sys.argv[1], "rb").read()
i = raw.find(b"Set-Cookie: PHPSESSID=")
if i < 0:
    print("no_cookie resp=%d" % len(raw)); raise SystemExit(1)
v = raw[i + len("Set-Cookie: PHPSESSID="):].split(b"\r\n")[0]
dec = urllib.parse.unquote_to_bytes(v.decode("latin1"))
c = Counter(); first = {}
for off in range(0, len(dec) - 8, 8):
    q = struct.unpack_from("<Q", dec, off)[0]
    if 0x500000000000 <= q <= 0x7fffffffffff:
        b = q & ~0x1fffff
        c[b] += 1; first.setdefault(b, (off, q))
print("decoded=%d head=%r clusters=%d ptrs=%d" % (
    len(dec), dec[:16], len(c), sum(c.values())))
for base, n in c.most_common(6):
    print("  %#x : %d first_off=%#x" % (base, n, first[base][0]))
