#!/usr/bin/env python3
"""
fix_ptr_range.py —— 修复 PHP2Shell 系 exploit 的指针过滤范围。

问题：几乎所有公开脚本都把用户态堆指针范围写死成
      0x7f0000000000 <= p <= 0x7fffffffffff
但 Linux x86-64 的 mmap 落点取决于 ASLR 和内核策略，实测见过 0x76xx / 0x7cxx / 0x72xx。

症状（很迷惑）：
  - 泄漏请求本身是成功的（Set-Cookie 返回 4096 / 819208 字节）
  - hexdump 里确实有 0x76a9108a70a0 这类指针
  - 但解析函数返回 0，报 "no heap pointers"
  - 容易误判成"堆布局变了，要重新标定"

用法：
  python3 scripts/fix_ptr_range.py <目标目录或文件> [更多...]
  python3 scripts/fix_ptr_range.py php8.5.11 php8.4.26 scripts

不带参数时，自动扫描当前目录下所有 .py 文件。
"""
import os
import re
import sys

# 匹配各种写死的 0x7f 下界（大小写都覆盖）
PATTERNS = [
    (re.compile(r"0x0?[7F]{2}0000000000", re.IGNORECASE), "0x500000000000"),
    (re.compile(r"0x0?7[Ff]0000000000"), "0x500000000000"),
]

REPLACEMENT = "0x500000000000"


def patch_text(s: str) -> tuple[str, int]:
    n = 0
    for pat, rep in PATTERNS:
        s, k = pat.subn(rep, s)
        n += k
    return s, n


def fix_file(path: str, dry: bool = False) -> int:
    try:
        with open(path, "r", encoding="utf-8") as f:
            s = f.read()
    except (UnicodeDecodeError, OSError):
        return 0

    new, n = patch_text(s)
    if n == 0:
        return 0
    if not dry:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new)
    return n


def walk(target: str, dry: bool) -> tuple[int, int]:
    files = changed = 0
    if os.path.isfile(target):
        c = fix_file(target, dry)
        if c:
            print(("  [dry] " if dry else "  [fix] ") + target + f"  ({c} 处)")
            return 1, 1
        return 1, 0

    for root, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if d not in (".git", "__pycache__", "out", "node_modules")]
        for name in names:
            if not name.endswith(".py"):
                continue
            if name == "fix_ptr_range.py":   # 别把自己改了
                continue
            p = os.path.join(root, name)
            c = fix_file(p, dry)
            files += 1
            if c:
                changed += 1
                print(("  [dry] " if dry else "  [fix] ") + p + f"  ({c} 处)")
    return files, changed


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    dry = "-n" in sys.argv or "--dry-run" in sys.argv

    targets = args or ["."]
    total_files = total_changed = 0
    for t in targets:
        if not os.path.exists(t):
            print(f"跳过（不存在）：{t}")
            continue
        f, c = walk(t, dry)
        total_files += f
        total_changed += c

    print()
    print(f"扫描 {total_files} 个 .py 文件，需要修改 {total_changed} 个")
    if dry and total_changed:
        print("这是 dry-run，去掉 -n / --dry-run 才会真正写入")
    if total_changed:
        print("\n修改后请重新验证：")
        print("  python3 exploit.py -u http://TARGET/index.php --zif-offset 0x... --dtor-offset 0x...")


if __name__ == "__main__":
    main()
