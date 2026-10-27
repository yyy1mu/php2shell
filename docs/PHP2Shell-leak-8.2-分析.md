# PHP2Shell leak 原语在 PHP 8.2 上的复现与分析

**日期**: 2026-10-22
**环境**: 101.200.220.128（Debian 13 trixie, x86_64, Docker 26.1.5）→ Termark 会话内临时密钥 `tunnel_key`（`php2shell-tunnel-ephemeral`）
**镜像**: `php:8.2-apache` / `php:8.2-cli`（PHP 8.2.35，经反代 7897 → 本机 Clash 拉取）
**实验配置**: 复刻 `php-cve-2026-10961x-lab-poc` 的 `lab.ini`（memory_limit=16M、display_errors=1、upload_progress=1、session.save_path=/tmp）+ `mpm_prefork.conf`（单 worker）+ `--internal` 网络 + 256MB 内存限制

---

## 1. leak 流程实测（3 轮）

| 轮次 | leak-A（OOM） | leak-B（900 字段 + forge-len 0x1000） | barr（257 元素单数组） | worker |
|---|---|---|---|---|
| 1 | 200 / 668B，OOM fatal | 200 / 233B，cookie `PHPSESSID=7555…`（32 hex） | 200，cookie `03dc…`（32 hex） | pid 17 → 17 |
| 2 | 200 / 668B，OOM fatal | 200，cookie `a2c5…`（32 hex） | 200，cookie `7d4d…`（32 hex） | 17 → 17 |
| 3 | 200 / 668B，OOM fatal | 200，cookie `0573…`（32 hex） | 200，cookie `e59e…`（32 hex） | 17 → 17 |

- **leak-B 从未返回 512 字节 PHPSESSID**，全部是标准 32 字节回退 id。
- 257 元素数组（仓库声称的 reclaim 载体）同样只得到 32 字节 id。
- worker 全程 pid 稳定，无 `zend_mm_heap corrupted`、无 segfault。
- session 文件按**新生成的 id** 创建（`/tmp/sess_7555…` 等），说明 `php_session_initialize()` 走的是 regenerate 分支，而非复用任何"悬空"内容。

Apache 日志（A 请求）稳定复现三个事件，顺序固定：

```
PHP Warning: PHP Request Startup: Input variables exceeded 1000. … in Unknown on line 0
PHP Warning: PHP Request Startup: Session cookie cannot be sent after headers have already been sent in Unknown on line 0
PHP Fatal error: Allowed memory size of 16777216 bytes exhausted (tried to allocate 6299648 bytes) in Unknown on line 0
```

第二条警告证明 **A 请求中 rfc1867 路径确实初始化了 session 并生成了新 id**（`PS(id)` 被赋值为请求堆上的 zend_string），随后 OOM。但 `session.upload_progress.cleanup=0` 下 `/tmp` **仍无任何 `sess_*` 文件**——A 的 session 初始化在 s_open/写入阶段没有落盘。这是"12/12 fires 从 leak 开始"声称的又一处反证。

---

## 2. 源码级对照（8.2.35 vs 8.5.11 vs 8.5.12）

### 2.1 `PS(id)` 类型三者相同：`zend_string *`

```c
/* 8.2.35 session.c:1452 */
PS(id) = zend_string_init(Z_STRVAL_P(ppid), Z_STRLEN_P(ppid), 0);
```
8.2.35 中 `PS(id)` 已是 zend_string（`ZSTR_VAL(PS(id))[0]`、`zend_string_release_ex` 均在用），与 8.5.11 完全一致。因此"8.2 结构不同、尺寸前提不成立"的猜想被否定——**32 hex id = 24B 头 + 32B 数据 + NUL = 57B → 64 字节 bin**，与 8.5 一致。

### 2.2 跨请求悬空前提在 8.2 **直接不成立**

```c
/* 8.2.35 session.c:107-120  RINIT */
static inline void php_rinit_session_globals(void) {
    PS(id) = NULL;                       // 每次请求开始清空
    PS(session_status) = php_session_none;
    ...
}

/* 8.2.35 session.c:129-141  RSHUTDOWN */
static void php_rshutdown_session_globals(void) {
    ...
    if (PS(id)) {
        zend_string_release_ex(PS(id), 0);   // 无条件释放
        PS(id) = NULL;                        // 无条件置空
    }
    ...
}
```

请求 A 无论怎么 OOM，`php_request_shutdown` 的模块 RSHUTDOWN 都会执行到这段：**A 的 `PS(id)` 被释放并置 NULL**。请求 B 的 RINIT 再清一次。leak 声称所需的"请求 B 读到请求 A 的悬空 `PS(id)`"在 8.2 上不存在任何代码路径。

### 2.3 尺寸隔离在 8.2 同样成立

报告 §3.2a 的尺寸论证对 8.2 逐字适用：
- `PS(id)`：57B → `free_slot[7]`（64B bin）
- 257 元素数组：`sizeof(zend_array)=56` + 257×`sizeof(Bucket)=32` = **8280B** → 超出 30 个 bin，走 `_zend_mm_alloc` 大块路径
- 两者不在同一 size class；请求堆由 `shutdown_memory_manager` **整批回收**，不存在"大块落入小 slot"

8.2 没有 8.5 的 `shadow_key`（free list 指针 XOR 加密），free list 是明文指针——但这只影响"篡改 free list"类原语，**不改变 size class 硬隔离**，也不影响"整批回收"。

### 2.4 关键发现：`in_rfc1867_update` 在 8.2 有、8.5.11 丢了、8.5.12 补回

| 版本 | `PS(in_rfc1867_update)` | rfc1867 update/cleanup 写法 |
|---|---|---|
| **8.2.35** | ✅ 120/857/865/3005 行 | `PS(in_rfc1867_update)=true;` + `if (php_session_initialize()==FAILURE \|\| session_status!=active) { …=false; return; }` + 末尾复位 |
| **8.5.11** | ❌ **完全不存在** | `php_session_initialize(); PS(session_status) = php_session_active;`（无保护、无失败检查、**无条件置 active**） |
| **8.5.12** | ✅ 123/966/974/2971/3181 行，cleanup 另有 3195-3211 | 恢复 8.2 式保护，且比 8.2 更细 |

即原报告 §2.1 只写了"8.5.12 补丁增加 `PS(in_rfc1867_update)` 标记 + `php_session_initialize` 失败检查"，**没指出这是 8.5 分支相对 8.2 的回归（regression），8.5.12 是把 8.2 已有逻辑回迁**。同类的 `incomplete_classes_only`（`php_session_unserialize_init` 里 `if (PS(in_rfc1867_update))`）在 8.2.35 也已存在。

---

## 3. 8.2 上缺什么（原语面差异）

| 原语/机制 | 8.2.35 | 8.5.11 | 8.5.12 |
|---|---|---|---|
| `PS(id)` 为 zend_string | ✅ | ✅ | ✅ |
| RINIT/RSHUTDOWN 无条件清 `PS(id)` | ✅ | ✅ | ✅ |
| `in_rfc1867_update` session 保护 | ✅ | ❌（回归） | ✅ |
| `fatal_error_backtraces` INI + `EG(last_fatal_error_backtrace)` | ❌ 不存在 | ✅ | ✅（shutdown 无条件 UNDEF） |
| `delayed_oom` 状态机 / `UnwindExit` | ❌ | ❌ | ✅ |
| Zend MM `shadow_key` | ❌ | ✅ | ✅ |
| `memory_hard_limit_percent` | ❌ | ❌ | ✅ |

结论：**报告 §2.2 的 backtrace-UAF 原语在 8.2 根本不存在**（`fatal_error_backtraces` 是 8.5 新增），8.2 上不是"难度更低"，而是这条原语整个消失。反过来，8.5.11 相对 8.2 是**功能回退**版本，它的 rfc1867 路径少了 8.2 一直有的状态保护。

---

## 4. 回答"8.2 是否降低攻击难度"

**不降低，反而更难**，三个独立理由：

1. leak 的悬空前提在 8.2 被 RINIT/RSHUTDOWN 双重清除，无代码路径；
2. 尺寸隔离（57B/64B bin vs 8280B 大块 + 整批回收）与 8.2/8.5 无关，纯分配器语义；
3. 8.5 才有的 backtrace / delayed-OOM / shadow_key 原语面在 8.2 不存在，且 8.2 的 rfc1867 session 保护是 8.5.11 缺失的那层。

**真正值得优先修的资产是 8.5.11（及同分支 8.5.0–8.5.11）**：它同时具备"缺 in_rfc1867_update 保护"和"8.5 新增原语面"两个条件。8.2.x 在本链路上不构成同等暴露面。

---

## 5. 对原报告的补充

1. 原报告 §3.2 的三条反证在 8.2 上全部复验成立，并新增一条机制性证据：`PS(id)` 生命周期被 RSHUTDOWN 强制终结。
2. 原报告 §2.1 的补丁条目应改写为"**回迁 8.2 分支已有加固**（`in_rfc1867_update`、`incomplete_classes_only`）+ 8.5 自身新增项（`delayed_oom`、`memory_hard_limit_percent`、shutdown 无条件 UNDEF）"。
3. 实验补充：A 请求的 session 初始化在 `cleanup=0` 下仍不落盘，说明该请求的 session 生命周期在 OOM 前未完成，进一步削弱"leak 起点"的可信度。

---

*实验容器已清理；反向代理隧道保留（远端 127.0.0.1:7897 → 本机 Clash，供远端 docker 拉镜像用）。*
