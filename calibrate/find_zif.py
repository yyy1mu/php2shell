#!/usr/bin/env python3
"""在 stripped 的 PHP 二进制里定位 zif_system（发行版包没有 .symtab 时用）。

原理：PHP 8 的内部函数表 `zend_function_entry` 在 .data.rel.ro 里是定长记录：

    struct _zend_function_entry {
        const char *fname;            // +0x00  指向 "system"
        zif_handler handler;          // +0x08  → zif_system，就是我们要的地址
        const zend_internal_arg_info *arg_info;  // +0x10
        uint32_t num_args;            // +0x18
        uint32_t flags;               // +0x1c
    };                                // 32 字节

所以：找 "system\\0" 字符串 → 找指向它的指针（记录起点）→ 验 num_args/flags →
读 handler。全程不需要符号表。

用法：
    python3 find_zif.py /path/to/libphp8.2.so [函数名...]
"""

from __future__ import annotations

import struct
import sys

REC = 32
FNAME, HANDLER, ARG_INFO, NUM_ARGS, FLAGS = 0x00, 0x08, 0x10, 0x18, 0x1C


class Elf:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
            raise SystemExit("不是 little-endian ELF64")
        self.data = data
        e_phoff, = struct.unpack_from("<Q", data, 0x20)
        e_shoff, = struct.unpack_from("<Q", data, 0x28)
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
        e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)

        self.loads = []          # (vaddr, offset, filesz)
        for i in range(e_phnum):
            off = e_phoff + i * e_phentsize
            p_type, = struct.unpack_from("<I", data, off)
            p_offset, = struct.unpack_from("<Q", data, off + 8)
            p_vaddr, = struct.unpack_from("<Q", data, off + 16)
            p_filesz, = struct.unpack_from("<Q", data, off + 32)
            if p_type == 1 and p_filesz:
                self.loads.append((p_vaddr, p_offset, p_filesz))

        self.sections = []       # (name, vaddr, offset, size)
        shstr_off = shstr_size = 0
        raw = []
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            sh_name, sh_type = struct.unpack_from("<II", data, off)
            sh_addr, sh_offset, sh_size = struct.unpack_from("<QQQ", data, off + 16)
            raw.append((sh_name, sh_type, sh_addr, sh_offset, sh_size))
        if raw:
            shstr_off = raw[e_shnum - 1][3]
            shstr_size = raw[e_shnum - 1][4]
            for sh_name, sh_type, sh_addr, sh_offset, sh_size in raw:
                if sh_type == 0:
                    continue
                end = data.find(b"\x00", shstr_off + sh_name)
                name = data[shstr_off + sh_name:end].decode("ascii", "replace")
                if name in (".text", ".data.rel.ro", ".rodata", ".data",
                            ".data.rel.ro.local", ".init_array"):
                    self.sections.append((name, sh_addr, sh_offset, sh_size))

    def vaddr(self, file_off: int) -> int:
        for p_vaddr, p_offset, p_filesz in self.loads:
            if p_offset <= file_off < p_offset + p_filesz:
                return p_vaddr + (file_off - p_offset)
        return 0

    def first_load(self) -> int:
        return min(v for v, _, _ in self.loads)

    def in_text(self, addr: int) -> bool:
        for name, va, off, size in self.sections:
            if name == ".text" and va <= addr < va + size:
                return True
        return False

    def contains_symtab(self) -> bool:
        return any(t == 2 for _, t, _, _, _ in
                   [(0, 0, 0, 0, 0)]) or b".symtab" in self.data[:0x10000]


def scan(data: bytes, elf: Elf, fname: bytes) -> list[tuple[int, int, int, int]]:
    """返回 [(handler_vaddr, record_vaddr, num_args, flags)]"""
    needle = fname + b"\x00"
    str_addrs = []
    start = 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            break
        # 排除 "system" 出现在其它字符串中间（如 "clearstatcache" 之类）
        addr = elf.vaddr(i)
        if addr:
            str_addrs.append(addr)
        start = i + 1

    hits = []
    for addr in str_addrs:
        ptr = struct.pack("<Q", addr)
        pos = 0
        while True:
            j = data.find(ptr, pos)
            if j < 0:
                break
            pos = j + 1
            if j + REC > len(data):
                continue
            handler, = struct.unpack_from("<Q", data, j + HANDLER)
            num_args, flags = struct.unpack_from("<II", data, j + NUM_ARGS)
            if handler and elf.in_text(handler) and 0 < num_args < 32:
                hits.append((handler, elf.vaddr(j), num_args, flags))
    return hits


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    path = sys.argv[1]
    names = sys.argv[2:] or ["system"]
    data = open(path, "rb").read()
    elf = Elf(data)
    base = elf.first_load()

    print(f"file        {path}")
    print(f"size        {len(data):,}  bytes")
    print(f"PT_LOAD 最小 vaddr = 0x{base:x}（加载基址 = 运行时地址 - 该值）")
    print(f"sections    {', '.join(f'{n}@0x{va:x}' for n, va, _, _ in elf.sections)}")
    print()
    for name in names:
        hits = scan(data, elf, name.encode())
        if not hits:
            print(f"[{name}] 没找到候选（可能不是 ZEND_FUNCTION 表里的名字）")
            continue
        for handler, rec, num_args, flags in hits[:6]:
            print(f"[{name}] record@0x{rec:x}  num_args={num_args} flags=0x{flags:x}  "
                  f"handler=0x{handler:x}  → 相对加载基址偏移 0x{handler - base:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
