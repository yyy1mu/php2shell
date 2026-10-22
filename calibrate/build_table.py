#!/usr/bin/env python3
"""calibration.json → CALIBRATION.md（表由数据生成，避免文档和标定漂移）。

    python3 calibrate/build_table.py            # 写 ../CALIBRATION.md
    python3 calibrate/build_table.py --check    # 只比对，不写（CI 用）

CALIBRATION.md 里有两块是手写的：文件头说明和尾部的"怎么用/怎么扩"——它们放在
calibrate/CALIBRATION.head.md 和 calibrate/CALIBRATION.tail.md，本脚本负责把表插到
两者中间。
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TABLE = os.path.join(ROOT, "calibration.json")
HEAD = os.path.join(HERE, "CALIBRATION.head.md")
TAIL = os.path.join(HERE, "CALIBRATION.tail.md")
OUT = os.path.join(ROOT, "CALIBRATION.md")

STATUS_LABEL = {
    "exploitable": "✅ 可利用",
    "patched": "🛡 已修复",
    "partial": "⚠️ 部分（泄漏通、stage3 待标）",
    "broken": "⚠️ 链不适用",
    "unverified": "❔ 未验证",
}


def short_digest(dig: str) -> str:
    if not dig:
        return "_(本地构建)_"
    body = dig.split(":", 1)[-1]
    return f"`{body[:12]}…{body[-6:]}`"


def proof_text(e: dict) -> str:
    ev = e.get("evidence") or {}
    if e.get("verified") is True:
        p = (e.get("run") or {}).get("proof") or ev.get("proof") or "PROOF"
        att = ev.get("attempts") or []
        n_ok = sum(1 for a in att if a.get("ok"))
        tail = f"（{n_ok}/{len(att)} 次运行）" if len(att) > 1 else ""
        return "`" + p[:34] + "`" + tail
    if e.get("verified") is False:
        if not ev.get("attempts") and e.get("status") in ("patched", "broken"):
            return "—（只采符号）"
        return "❌ 未打通"
    return "—"


def row(e: dict) -> str:
    heap = e.get("heap") or {}
    proof = proof_text(e)
    return "| {v} | {tag} | {dig} | `{z}` | `{d}` | `{dl}` | {heap} | {st} | {p} |".format(
        v=e.get("php_version", "?"),
        tag=f"`{e.get('tag', '')}`",
        dig=short_digest(e.get("repo_digest", "")),
        z=e.get("zif_system", "—"),
        d=e.get("zval_ptr_dtor", "—"),
        dl=e.get("delta_dtor_to_zif", "—"),
        heap=heap.get("profile", "—"),
        st=STATUS_LABEL.get(e.get("status", ""), e.get("status", "?")),
        p=proof,
    )


def render(table: dict) -> str:
    head = open(HEAD, encoding="utf-8").read() if os.path.exists(HEAD) else ""
    tail = open(TAIL, encoding="utf-8").read() if os.path.exists(TAIL) else ""

    lines = ["| PHP | 镜像 tag | digest | `zif_system` | `zval_ptr_dtor` | delta | 堆标定 | 状态 | 实测 |",
             "|---|---|---|---|---|---|---|---|---|"]
    lines += [row(e) for e in table["images"]]
    body = "\n".join(lines)

    fams: dict[str, list[dict]] = {}
    for e in table["images"]:
        fams.setdefault((e.get("heap") or {}).get("profile", "?"), []).append(e)
    fam_lines = ["", "### 按堆标定族汇总", ""]
    for fam, items in fams.items():
        ok = [i for i in items if i.get("verified") is True]
        bad = [i for i in items if i.get("status") == "patched"]
        heap = items[0].get("heap") or {}
        vers = "、".join(i.get("php_version", "?") for i in items)
        fam_lines.append(
            f"- **{fam}**：htdata=`{heap.get('htdata')}` · stage1_n=`{heap.get('stage1_n')}` "
            f"· stage2_t=`{heap.get('stage2_t')}` · stage2_v=`{heap.get('stage2_v')}` "
            f"· pads={heap.get('stage3_pads')} · SID=`{heap.get('sid')}`"
        )
        fam_lines.append(
            f"  - 覆盖 {len(items)} 个镜像（{vers}）：实测打通 {len(ok)} 个"
            + (f"；另有 {len(bad)} 个已修复版未打通（是漏洞被修，不是标定错）" if bad else "")
        )
    fam_lines.append("")

    repro = ["## 各可利用镜像的复现命令", ""]
    any_repro = False
    for e in table["images"]:
        if e.get("status") != "exploitable":
            continue
        cmd = (e.get("evidence") or {}).get("cmd")
        if not cmd:
            continue
        any_repro = True
        repro.append(f"- **PHP {e.get('php_version')}**（digest `{(e.get('repo_digest') or '').split(':',1)[-1][:16]}…`）")
        repro.append("")
        repro.append("  ```bash")
        repro.append(f"  {cmd}")
        repro.append("  ```")
    if not any_repro:
        repro = []

    blocks = [head, body, "\n".join(fam_lines)]
    if table.get("binaries"):
        bl = ["### 非镜像目标（拿到的二进制）", "",
              "不是从镜像起来的 PHP（apt/yum 包、自编译、别人的服务器上抠出来的 .so）按**二进制 sha256** 记，",
              "因为发行版会 strip 掉 `.symtab`，`zif_system` 得靠函数表扫描找（`calibrate/find_zif.py`）。", "",
              "| 二进制 | 来源 | `zif_system` | `zval_ptr_dtor` | delta | 符号表 | 堆标定 |",
              "|---|---|---|---|---|---|---|"]
        for b in table["binaries"]:
            bl.append("| `{}` | {} | `{}` | `{}` | `{}` | {} | {} |".format(
                b.get("binary"), b.get("source", ""),
                b.get("zif_system"), b.get("zval_ptr_dtor"), b.get("delta_dtor_to_zif"),
                "stripped（无 .symtab）" if b.get("stripped") else "有 .symtab",
                b.get("heap", "—")))
        bl.append("")
        bl.append("细节：`calibration.json` 的 `binaries` 段（含 sha256、验证方式）。")
        blocks.append("\n".join(bl))
    if repro:
        blocks.append("\n".join(repro))
    blocks.append(tail)
    return "\n\n".join(b.strip("\n") for b in blocks if b.strip()) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()

    table = json.load(open(TABLE, encoding="utf-8"))
    md = render(table)

    if args.check:
        cur = open(OUT, encoding="utf-8").read() if os.path.exists(OUT) else ""
        if cur != md:
            print("CALIBRATION.md 与 calibration.json 不一致", file=sys.stderr)
            return 1
        print("一致")
        return 0

    with open(OUT, "w", encoding="utf-8") as f:
        f.write(md)
    print(f"wrote {OUT} ({len(table['images'])} 个镜像)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
