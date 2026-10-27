# 变更记录

## 2026-10-27 — 实测定稿

本轮在两台独立机器上把三条链都跑了一遍，补齐了"什么能打、什么打不了、为什么"。

### 新增

- **`FINDINGS.md`** — 本轮全部实测结论汇总：
  - 三条链（mod_php+display_errors=On / mod_php+Off+128M / FPM）的机制与前提
  - 6 个踩过的坑，每个都带症状和判断方法
  - 各版本可利用性矩阵、修复版本对照
  - 检测规则与缓解措施
- **`scripts/fix_ptr_range.py`** — 自动修复指针过滤范围。
  换环境打不通的第一嫌疑：`0x7F0000000000` 写死，而 ASLR 可能落在 `0x76xx` 段。
- **`scripts/pure_128M_exploit.py`** — `display_errors=Off` + 128M + 150 worker 的全链脚本。
- **`scripts/mk_a1.py` / `mk_leak_b.py` / `chunked_send.py` / `decode_cookie.py`** — pure 链的构造与解码工具。
- **`docs/RESEARCH_PURE_128M.md`** — pure 链的研究笔记。
- **`docs/PHP2Shell-8.5.11-漏洞深度分析.md`** — 本轮的深度分析（含 gdb 证据）。
- **`docs/PHP2Shell-leak-8.2-分析.md`** — 8.2 泄漏路径分析。

### 修复

- `php8.5.11/exploit.py`、`php8.4.26/exploit.py`：指针下界 `0x7F0000000000` → `0x500000000000`。
  之前在两台机器上打不通，根因就是这个，**不是堆布局问题**。
- `scripts/decode_cookie.py`、`scripts/pure_128M_exploit.py`：同上。

### 实测结论

| 环境 | 结果 |
|---|---|
| 8.5.11 / display_errors=On / 8M / 单 worker | ✅ `uid=33(www-data)`，3/3 |
| 8.5.11 / display_errors=On / 8M / 150 worker | ✅ RCE |
| 8.4.26 / display_errors=On / 8M / 单 worker | ✅ `uid=33(www-data)`，3/3 |
| 8.4.26 / **display_errors=Off** / **128M** / **150 worker** | ✅ **`uid=33(www-data)`，3/3** |
| nginx + php-fpm 8.5.11（单/多 worker） | ❌ 链不适用（FPM 杀 worker） |
| PHP 7.4.21 mod_php | ❌ 链不适用（`reset_id` 清零语义） |

### 关键认知

1. **`display_errors=Off` 不构成防御** — 换 pure 链照样 RCE。
2. **偏移跟二进制走，不跟版本号走** — 同版本不同构建偏移不同。
3. **指针范围要按实际 ASLR 段判断** — 别写死 `0x7f`。
4. **FPM 不是 mod_php 的等价目标** — worker 生命周期完全不同，链不通用。
