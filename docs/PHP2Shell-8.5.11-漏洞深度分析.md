# PHP 8.5.11 漏洞深度分析（gdb 实测 + 源码级）

**日期**: 2026-10-22
**环境**: 101.200.220.128（Debian 13, x86_64, Docker 26.1.5）
**镜像**: `php:8.5.11-apache` / `php:8.5.12-apache`（自建 `*-gdb` 变体，容器内 gdb 16.3 + `--cap-add=SYS_PTRACE`）
**方法**: libphp.so 未 strip，`executor_globals`/`zend_error_zstr_at`/`zend_shutdown_executor_values`/`zend_fetch_debug_backtrace`/`shutdown_memory_manager` 全为动态符号，直接下断点读 `EG(last_fatal_error_backtrace)` 的 zval 头。

---

## 1. 全量补丁对照（8.5.11 → 8.5.12 的安全相关点）

| 文件 | 8.5.11 | 8.5.12 |
|---|---|---|
| `Zend/zend_execute_API.c` | `fast_shutdown=1` 时 **不** 清 `EG(last_fatal_error_backtrace)`；`EG(errors)/error_handling/exception/objects_store` 残留 | `zend_shutdown_executor_values()` **末尾无条件** `ZVAL_UNDEF(&EG(last_fatal_error_backtrace))` + 重置 `record_errors/num_errors/errors/error_handling/exception`；`fast_shutdown` 分支也清 `objects_store.object_buckets/top`（注释：*may be used by zend_error_zstr_at before init_executor*） |
| `ext/session/session.c` | 无 `PS(in_rfc1867_update)`；`php_session_rfc1867_update/cleanup` 里 `php_session_initialize(); PS(session_status)=php_session_active;` 无失败检查；strict-mode 的 `s_create_sid` 失败则 `PS(id)=php_session_create_id(NULL)`（可能为 NULL 仍继续） | 增加 `PS(in_rfc1867_update)`；失败即 `php_session_abort()`；`s_create_sid` 失败 → throw + `return FAILURE`；`php_session_unserialize_init()` 用 `incomplete_classes_only`（RINIT 前不执行用户代码） |
| `Zend/zend.c` | 无 `delayed_oom` 状态机 | `EG(delayed_oom)` 初始化/memset/`zend_mm_oom_info_dtor`；`zend_execute` 后 `zend_handle_delayed_oom()`；fatal 处理加 `state != ZEND_OOM_STATE_HANDLING` 条件 |
| `main/SAPI.c` | 无 | post handler 后 `if (ZEND_HAS_OOM()) zend_handle_delayed_oom();` |
| `main/rfc1867.c` | 无 OOM 检查 | 大量 `ZEND_HAS_OOM()` 检查；`add_protected_variable` 等返回 bool |
| `main/php_variables.c` | 无 | `ZEND_HAS_OOM()` 提前返回；`array_init_singleton`（延迟数组） |
| `Zend/zend_alloc.c` | 无 | `delayed_oom` 分支 + 可失败分配 |

**8.5.11 完全没有 `delayed_oom` / `ZEND_HAS_OOM` / `zend_handle_delayed_oom`**（源码 grep 为空）。OOM 仍走 `zend_bailout`（longjmp），跳过 C 栈清理。

---

## 2. 主原语实证：`EG(last_fatal_error_backtrace)` 跨请求悬空

### 2.1 gdb 观测（同一脚本，两版对照）

| 观测点 | **8.5.11** | **8.5.12** |
|---|---|---|
| A 请求 fatal 时 `&EG(bt)` | `0x7f07e1788ab0` | `0x7f3548b88bb0` |
| A `zend_shutdown_executor_values` 入口 `fast` | 1 | 1 |
| A shutdown 入口 `bt_type` | **775**（`IS_ARRAY`，refcount 3） | **775** |
| B 请求 `zend_activate`（init_executor）**之前** `bt_type` | **775 ← 悬空数组，val 仍指向 A 已释放的请求堆** | **0 ← IS_UNDEF，已被无条件清除** |
| B 请求结束后 | 0（被 `init_executor` 覆盖） | 0 |

原始输出见 [gdb-8511-backtrace.out](gdb-8511-backtrace.out) / [gdb-8512-backtrace.out](gdb-8512-backtrace.out)。

### 2.2 机制解读

8.5.11 请求 A 的 fatal 路径：
```
zend_error_zstr_at(E_ERROR)
  → zend_fetch_debug_backtrace(&EG(last_fatal_error_backtrace))   ← gdb 断点命中
  → php_request_shutdown
     → zend_shutdown_executor_values(fast_shutdown=1)
        → if (!fast_shutdown) { zval_ptr_dtor(&EG(bt)); ZVAL_UNDEF(bt); }   ← 跳过！
     → shutdown_memory_manager()   ← 释放 A 的整个请求堆 → bt_val 指向的内存失效
```

**请求 B 的 `init_executor` 之前，`EG(bt)` 仍是 `IS_ARRAY` 且指向已释放内存 = 悬空 zval。** 8.5.12 在 `zend_shutdown_executor_values()` 末尾无条件清洗，使 B 启动时该 zval 已是 `IS_UNDEF`——窗口被彻底消除。

### 2.3 悬空状态如何变成 UAF

`zend_error_zstr_at` 的 fatal 路径（`zend.c:1506` 附近）有一句无条件的：

```c
zval_ptr_dtor(&EG(last_fatal_error_backtrace));
ZVAL_UNDEF(&EG(last_fatal_error_backtrace));
```

若请求 B **在 `init_executor` 之前**产生任意 fatal（E_ERROR/E_PARSE/E_CORE_ERROR 等，且非 `E_DONT_BAIL`），就会对悬空 zval 执行 `zval_ptr_dtor`：
- 指针仍映射 → 按残留内容解释为 `zend_array` 并释放其元素（可控的任意 `pDestructor` 调用面）
- 指针已 unmapped → SIGSEGV（worker 崩溃 → DoS）

### 2.4 触发窗口实测（为什么"打不到"）

穷举 `init_executor` 之前可能产生 fatal 的入口，全部实测排除：

| 候选路径 | 实测结果 |
|---|---|
| `apache2handler` 的 `php_apache_request_ctor`（读 header） | 无 `zend_error` 调用 |
| `php_request_startup` 内部 | 第一步就是 `zend_activate → init_executor`，之后才可能有错误 |
| `.htaccess` 的 `php_value`（`apply_config`） | 失败只走 `phpapdebug`，不打 `zend_error`（8.5.4/8.5.11 逐行相同） |
| 404/403 路径 | 只调 `ap_log_rerror` |
| **压低 `memory_limit` 逼 startup OOM** | **PHP 拒绝设置**：`Failed to set memory limit to 1048576 bytes (Current memory usage is 2097152 bytes)`；1M/512K 均无效，B 请求正常 200 |
| `max_input_vars` 溢出 / `headers already sent` | 是 `E_WARNING`，`zend_error_zstr_at` 在非 fatal 分支直接 `return`，**不执行** `zval_ptr_dtor` |

**结论**：8.5.11 上悬空状态 100% 存在（gdb 实锤），但默认 Apache + mod_php 配置下 `init_executor` 之前没有 fatal 源，纯 HTTP 请求无法把悬空状态推进到 `zval_ptr_dtor`。这与仓库 `PROVEN-LAB-VERDICT.md` 自认 "Lab-Assisted" 一致——真打需要非默认 SAPI/扩展路径（fiber shutdown、扩展 deactivator、FPM 早期错误等）。

---

## 3. 次原语实证：rfc1867 session 状态机破坏（8.5.11 独有）

### 3.1 代码对比

**8.2.35（有保护）**：
```c
PS(in_rfc1867_update) = true;
if (php_session_initialize() == FAILURE || PS(session_status) != php_session_active) {
    PS(in_rfc1867_update) = false;
    return;
}
...
PS(in_rfc1867_update) = false;
```

**8.5.11（保护丢失）**：
```c
php_session_initialize();                    // 返回值被无视
PS(session_status) = php_session_active;     // 强制置 active
IF_SESSION_VARS() { ... }
php_session_flush(1);                        // 对失败状态执行 flush（写盘）
```

**8.5.12**：恢复 8.2 的 `in_rfc1867_update` + 失败检查。

### 3.2 实测差异（`session.save_path` 指向不存在目录）

| 版本 | 日志 | 响应 |
|---|---|---|
| **8.5.11** | `Failed to read session data` ×2 + **`Failed to write session data (files)`** ← 读失败后仍写盘 | 1325B |
| **8.5.12** | `open failed` + `Failed to read session data` ×2，**无 write 失败** ← 失败后直接 return | 888B |

8.5.11 的 `php_session_initialize()` 在 `s_read` 失败后已 `php_session_abort()`（`mod_data=NULL`、`status=none`），但调用方仍把它**强制改回 active 并 flush** → `s_write` 在非法状态上执行。在 OOM 场景下若 `s_create_sid` 失败，`PS(id)` 可能为 NULL 而 `status=active`，后续 `s_write/s_close` 直接消费 NULL/半初始化结构。

### 3.3 危害定级

- 默认 files handler：仅产生写失败警告（状态不一致，无内存破坏）
- 自定义 handler（redis/memcached/用户实现）：`s_write(NULL id)` 可能空指针/越界 → worker 崩溃（DoS）
- 与 OOM 组合：`bailout` 跳过 progress 结构清理（8.5.11 无 delayed_oom），请求收尾时使用半初始化状态

---

## 4. 攻击链评估（"难点"在哪）

到"纯 HTTP 端到端 RCE"还差四步，每一环都断：

1. **地址泄露（leak）**：8.2/8.5 均无（`PS(id)` 尺寸隔离 + RSHUTDOWN 强清；512B cookie 不存在）
2. **触发 UAF**：8.5.11 悬空状态真实，但 `init_executor` 前无 fatal 源（本报告 §2.4 穷举）
3. **堆布局控制**：即使触发 dtor，需让悬空地址被"可控内容"复用（Zend MM 整批回收 + mmap 清零，控制面极窄）
4. **地址计算**：fire 原语（`pDestructor → zif_system`）需要精确地址，作者自己用 gdb 取（ASLR 下远程不可得）

**能落地的只有**：8.5.11 的 rfc1867 状态机破坏（DoS/状态不一致），非 RCE。

---

## 5. 结论

1. **漏洞本体真实**：8.5.11 的 `EG(last_fatal_error_backtrace)` 在 `fast_shutdown=1` 下跨越请求边界悬空，gdb 可稳定复现；8.5.12 的 `zend_shutdown_executor_values` 末尾无条件清洗是有效修复。
2. **默认 mod_php 下不可达**：`init_executor` 之前的 fatal 源不存在，`memory_limit` 无法压低（PHP 拒绝），非 fatal 警告不触发 `zval_ptr_dtor`。
3. **8.5.11 相对 8.2 是回退**：`in_rfc1867_update` 在 8.2 一直存在、8.5.11 丢失、8.5.12 回迁；8.2 的 `incomplete_classes_only` 同理。
4. **优先修复对象**：8.5.0–8.5.11（同时缺 session 保护 + 有 8.5 新原语面），而不是 8.2.x。

---

*所有实验容器已清理；`*-gdb` 镜像与 gdb 观测脚本保留在 lab 主机 `/root/gdbbuild`、`/root/gdb_bt*.sh` 供复现。*

---

## 6. 堆风水实做（2026-10-22 追加）

### 6.1 真正的悬空原语：`PS(id)`（不是 backtrace，也不是 257 数组）

8.5.11 上发 A（1001 变量 + 24MiB 字段 OOM）后，gdb 读 `ps_globals`（`ps_globals+0x010`）发现：

```
PS(id) = 0x7fd96a2b7580  → chunk+0xb7580
  at 0x…b7580: gc.refcount=1, type_info=0x16(IS_STRING), h=0, len=0x20(32)
  data: "7201a4b828f2839b160e9706954a4993"   ← A 生成的 session id
```

**A 的 OOM 发生在 `rfc1867` body 解析阶段（RINIT 之前）→ session 模块 RINIT 未执行 → RSHUTDOWN 被跳过 → `PS(id)` 连同 32 字节 id 字符串一起悬空**。字符串 refcount 仍为 1，内容完整，位于 chunk 的 64 字节 bin。

这就是仓库 leak-A 声称的 "PS(id) dangles at chunk+0xb75c0"（实测 +0xb7580，布局差 0x40），也解释了为什么 257 元素数组（8280B）必然失败：**要 reclaim 的是 64 字节 bin，不是大块**。

### 6.2 B 请求的字段数据能否覆盖该块（实测）

| 尝试 | 结果 |
|---|---|
| B = 300 × 32B 字段 | 块内容不变（未落位） |
| B = 2000 / 8000 / 20000 × 32B 字段 | **块被复用**，但内容是 PHP 新生成的 32 hex（新 session id），不是我们的 marker |
| B = 6000 × 32B "D…" marker | 同上，块内出现新的 32 hex id |
| carrier（56B 全 C） | 块内容变成非字符串结构（部分覆盖） |

结论：**该 64B 槽在下一个请求里被"新 session id 分配"优先占用**（这正是 `php_session_create_id` 的固定落位），用普通字段值抢不到；必须用 carrier（数据区跨过块头）才能覆盖其 `ZSTR_LEN`。

### 6.3 backtrace 链为什么不能靠 B 字段 groom（时序证明）

gdb 观测序列（A → G(POST) → B）：

```
ACTIVATE #1 → A 的 ERR/FETCH_BT → ACTIVATE #2(G) → ERR type=2 bt_type=0
```

G 请求的 `init_executor` 会把 `EG(last_fatal_error_backtrace)` 重置为 `IS_UNDEF`，而 B 的 body 解析又发生在 `init_executor` **之后**、消费者 warning 发生在**之前**——因此：
- backtrace consumer 能吃的只有 A 留下的字节（不可控）；
- B 的字段数据对 backtrace 链**结构性无效**。

要走到 `zend_array_destroy → pDestructor`，可行路径是 6.1 的 `PS(id)` 槽：用 carrier 覆盖其 `ZSTR_LEN`（伪造 512/更大长度）→ 让 `php_session_initialize` 把超长 id 当字符串处理 → 或进一步伪造 `zend_reference/zend_array` 结构。

### 6.4 下一步（未完成）

1. 构造 carrier：请求体里放一个 `zend_string`，使其 data 起点 = `stale_id-0x18`，从而覆盖 `gc/type_info/h/len` 四字段；
2. 在 carrier 内伪造 `len=0x200`，观察 `Set-Cookie: PHPSESSID=…` 是否返回 512 字节（leak 复现）；
3. 若 leak 成立，再用同一 carrier 伪造 `zend_reference → zend_array → Bucket`，`pDestructor` 填可控值（先用 `0xdeadbeef` 验证 RIP 可控，再换 `zif_system`）。
4. 地址约束：`arData`/`pDestructor` 需要绝对地址，仍要靠信息泄露或 gdb 校准（作者的 lab-assisted 部分）。

### 6.5 carrier 伪造落地结果（2026-10-22 追加）

**伪造成功**：字段值长度 48（PHP 侧字符串 len=50，落 80B bin）时，carrier 数据覆盖 stale id 块：

```
P+0x00  refcount=0x30 type_info=0x0   (PHP 写的 len 字节)
P+0x08  h       = "HHHHHHHH"          (我们的数据)
P+0x10  len     = 0x200               (我们的数据) ← 伪造成功
P+0x18  data    = "LLLL..."           (我们的数据)
```

即 `PS(id)` 悬空指针指向的 zend_string 头部，`h/len/data` 三字段已被请求体完全控制。

**但 consumer 没有触发**：gdb 钩子（`php_session_reset_id` / `php_session_create_id`）显示本请求：

```
CREATE_ID #1                      ← php_session_initialize 走了"重新生成 id"分支
RESET_ID  #1 PS(id)=0x…85b000      ← 新 id（refcount=1,type=0x16,len=32）
```

说明进入 `php_session_initialize` 时 `PS(id)` 已经是 NULL——**RINIT（`php_rinit_session_globals`）在 body 解析之前把 `PS(id)` 清掉了**，悬空指针根本没被读到。这与仓库 leak-B 反复返回普通 32 字节 cookie 的实测完全一致。

**推论**：`PS(id)` 悬空虽然真实存在（A 之后 dump 可见），但跨请求消费它需要"body 解析早于 RINIT"——本 SAPI 顺序下不成立。因此 leak 链路（512 字节 cookie）在当前环境下**结构性不可达**，不是参数没调对。

**仍可试的方向**（未验证）：
1. `.htaccess` `php_value session.auto_start 1` → 在 RINIT 阶段起 session，但 RINIT 已先清 PS(id)，大概率同样无效；
2. 找"解析早于 RINIT"的 SAPI（FPM 的 `PHP_VALUE` 消费点、LSAPI）；
3. 转回 ninebie 的 `PS(http_session_vars)` reference 原语——本次 A 形状下它被 RSHUTDOWN 清成 UNDEF，需要换 A 形状（OOM 落在 session 初始化内部）。

### 6.6 三个方向实测结果（2026-10-22 追加，未拿到 leak）

**方向1：mod_php + carrier 伪造 `PS(id)` 头**

- 已确认启动顺序（gdb 断点实测）：`zend_activate → sapi_activate(解析 body) → php_session_reset_id → zend_activate_modules(RINIT)`，**解析确实早于 RINIT**；
- `PS(id)` 偏移经 `php_session_reset_id` 反汇编确认就是 `ps_globals+0x10`；
- carrier（48B 值，80B bin）可精确覆盖 stale 块：`P+8=h`、`P+0x10=len=0x200`、`P+0x18=data`（伪造成功）；
- 但 `php_session_initialize` 在多个请求形态下都走了 `php_session_create_id`（重新生成），说明读取时 `PS(id)` 已为空/首字节为 0；
- 8.5 新增限制是硬门槛：`max_input_vars`（默认 1000）与 **`max_multipart_body_parts`（默认 1020）**——后者直接截断大请求的后续 part，carrier 无法堆到目标槽位。
- 结论：伪造头的能力成立，但 consumer 窗口（解析期读到非空 stale id）在本环境下未能稳定命中。

**方向2：FPM（PHP_VALUE/PHP_ADMIN_VALUE）**——未执行
- 需要 nginx/mod_proxy_fcgi 前端；当前 lab 只有 apache mod_php。advisory 称 FPM 为条件暴露。

**方向3：ninebie `PS(http_session_vars)` reference 原语**——未成立
- 本次 A 形状（1001 变量 + 24MiB 字段）下，A 结束后 `ps_globals` 扫描无 `IS_REFERENCE` zval，RSHUTDOWN 已把 `http_session_vars` 清成 UNDEF；
- 需换 A 形状：让 OOM 落在 session 初始化内部（进度更新期间），或让 RINIT 不执行。

**对报告结论的再次确认**：仓库 leak 链路在官方镜像 8.5.11 上不可复现，与作者 PROOF-BOUNDARY 自认"无 in-band 地址泄露"一致。

---

## 7. FPM 方向：UAF 全链跑通（2026-10-22，关键结果）

### 7.1 环境

`php:8.5.11-fpm`（单 worker `pm=static, pm.max_children=1`）+ `nginx:alpine`（internal 网络），
nginx 用 `fastcgi_param PHP_VALUE "date.timezone=Foo/Bar"` 注入启动前诊断（FPM 在
`php_request_startup()` 之前应用 `PHP_VALUE`，即 **init_executor 之前**）。

### 7.2 因果对照（决定性）

| 配置 | A（/oom.php 应用层 OOM） | B（/diag，PHP_VALUE 诊断） | 结果 |
|---|---|---|---|
| `fatal_error_backtraces=1` | 200，fatal + Stack trace | **502** | **`zend_mm_heap corrupted` → SIGABRT（child exited on signal 6）** |
| `fatal_error_backtraces=0` | 200，fatal | 200 正常 | 无崩溃 |

### 7.3 gdb 崩溃栈（关键证据）

```
FETCH_BT  &=0x55cf076e5270            ← A 的 fatal 设置 backtrace
ERR type=2 bt_type=775 bt_val=0x7f5adf857118   ← B 的启动前诊断读到悬空 zval（IS_ARRAY）
Program received signal SIGABRT
#5  zend_array_destroy ()
#6  zend_array_destroy ()
#7  zend_array_destroy ()
#8  zend_error_zstr_at ()              ← B 的 PHP_VALUE 诊断路径
#9  php_verror ()
#10 php_error_docref ()
```

即：**B 请求在 `init_executor` 之前报诊断 → `zend_error_zstr_at` → `zval_ptr_dtor` 悬空 backtrace zval → `zend_array_destroy` 递归析构 → 堆损坏检测 abort**。

这与 advisory 对 CVE-2026-109619 的描述逐字吻合（"初始化前的 INI 诊断"consumer），
并且证明 **FPM 并非免疫**——app 层 OOM 作 producer、nginx 注入的 `PHP_VALUE` 作 consumer，
完全走通。

### 7.4 已拿到的"泄漏信息"

- 悬空数组地址：`0x7f5adf857118`（每次进程不同，ASLR）；
- `EG(last_fatal_error_backtrace)` 的固定偏移（FPM 二进制 `0x55cf076e5270`）；
- 完整析构路径与崩溃点（`zend_array_destroy` 递归 3 层）；
- 控制变量：`fatal_error_backtraces` 开关直接决定崩溃与否。

### 7.5 下一步（把 UAF 变成可控调用）

FPM 下 producer 是应用层可达的（任意 OOM 页面），consumer 是 nginx 配置注入，
**worker 常驻**（崩溃才重启），非常适合做堆风水：
用 A 的 multipart 字段在 chunk 内铺伪造 zend_array/Bucket，再让 B 的 PHP_VALUE 诊断消费，
把 `pDestructor` 填 `0xdeadbeef` 验证 RIP 可控。

### 7.6 可控 pDestructor（0xdeadbeef）尝试：结构性失败

**为什么做不到（关键结构约束）：**

`zend_array_destroy(Y)` 要走到 `pDestructor`，必须控制 Y 处的 zend_array 头
（refcount=1、type=IS_ARRAY、arData、nNumUsed、pDestructor）。但：

1. Y 是请求 A 里 `zend_fetch_debug_backtrace` **由 PHP 自己写**的数组头，写完后 A 立即 fatal，
   用户代码不再执行 → A 无法在 Y 处留下伪造头；
2. 消费者在 B 的 `init_executor` **之前**（`sapi_activate` 之前），B 的任何 PHP 分配都尚未发生
   → B 也无法在消费前 groom Y；
3. 因此在"backtrace 数组"这条链上，pDestructor 永远是 PHP 写入的真实函数指针（`zval_ptr_dtor`），
   只能打出堆损坏（DoS），打不出可控调用。

实测崩溃栈也印证：`zend_array_destroy` 递归三层后 abort，调用目标都是真实析构函数。

**换成 stale `EG(user_error_handler)` 的尝试（未成功）：**

- A 页面 `set_error_handler(闭包)` 后 OOM；B 用 `PHP_VALUE date.timezone=Foo/Bar` 触发诊断；
- `fatal_error_backtraces=1` 时仍先撞 backtrace 堆损坏（502 / SIGABRT）；
- `fatal_error_backtraces=0` 时 B 正常 200，闭包未被调用（`/tmp/hit.txt` 未生成）——
  该诊断走的是 SAPI 日志路径，未进入 `zend_error_zstr_at` 的 user_error_handler 分支。

**结论**：FPM 上 UAF→DoS 已完全打通（可复现、有因果对照、有崩溃栈），
但"可控 pDestructor"需要一个 **stale 全局指向攻击者可控内存** 的 producer；
backtrace 数组不满足（PHP 写头），下一步应转向 `PS(id)`/session 或 `EG(errors)` 这类
"指针在手、内容可灌"的 producer。

### 7.7 堆喷射多路径测试（2026-10-22）

在 FPM（单 worker、gdb 附加、`fatal_error_backtraces=1`）上跑了 4 组喷射形态，
每组都是 A（喷射后 OOM）→ B（PHP_VALUE 诊断）：

| 路径 | A 的喷射形态 | B 结果 | gdb 崩溃 |
|---|---|---|---|
| spray1 | 200k × 24–63B 小串，free 后 OOM | 502 | SIGABRT，`zend_mm_heap corrupted` |
| spray2 | 40k × 200–319B 中串，free 后 OOM | 502 | 同上，栈一致 |
| spray3 | 30 轮 × 5k × 48B 反复分配释放，后 OOM | 502 | 同上，栈一致 |
| baseline | 直接 OOM（无喷射） | 502 | 同上，栈一致 |

**结论：喷射不改变结果**。原因：
1. 悬空数组头 Y 由 `zend_fetch_debug_backtrace` 在 fatal 时写入，喷射只能在 A 的用户代码阶段铺数据，铺不到 Y；
2. 析构从 `zend_array_destroy` 的第一个无效 free 就被 Zend MM 的堆校验抓住并 abort，
   根本走不到可被喷射影响的 bucket 遍历分支。

**另外两条"内容可控"路径也验证为死路：**
- `EG(user_error_handler)`：A 用 `set_error_handler` 注册闭包（正常结束或 OOM 后），
  B 的启动前诊断**均未调用**该闭包（`/tmp/hit.txt` 未生成）——该全局在请求结束时被清，
  或 `EG(error_handling)` 不再是 `EH_NORMAL` 导致直接走 `zend_error_cb`；
- `EG(errors)`：`zend_begin_record_errors()` 在 8.5.11 源码中**没有用户态调用者**，
  `EG(record_errors)` 恒为 false → `safe_erealloc(EG(errors))` 分支不可达。

### 7.8 汇总判断

在官方 8.5.11 镜像 + 官方 SAPI（mod_php / FPM）组合下：
- **可达且可复现**：backtrace 悬空 → 启动前诊断消费 → `zend_array_destroy` → 堆校验 abort（DoS）；
- **不可达**：可控 `pDestructor`（需要"指针在手 + 内容可灌"的 producer，8.5.11 用户态没有）；
- 与 advisory 表述一致：RCE 需要"A strategically crafted heap layout"，而该布局依赖
  扩展/自定义 SAPI 等非默认条件。

---

## 8. 重大修正：公开 PoC 在 lab 复现成功，纯 HTTP RCE 成立（2026-10-22）

### 8.1 复现结果

在 lab 主机上原样复现 [9bie/php2shell-bypass-aslr-exp](https://github.com/9bie/php2shell-bypass-aslr-exp)：

**PHP 8.4.26（官方 `php:8.4.26-apache`，display_errors=On、memory_limit=8M）**

```
[+] chunk base = 0x7f9df8000000
[+] libphp base = 0x7f9df9bc1000
[+] W3 attempt 1
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**PHP 8.5.11（官方 `php:8.5.11-apache`，同一配置，偏移改为 8.5.11 符号）**

```
zif_system=0x5996e0  zval_ptr_dtor=0x7b47a0
[+] chunk base = 0x7f1824a00000
[+] libphp base = 0x7f1826400000
[+] HTDATA=0x7f1824a690d8 ZIF=0x7f18269996e0
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

第二次运行脚本报 "no proof" 但 `out/p3` 内容仍是 `uid=33(www-data)`——命令实际执行（blind），只是脚本的 proof 检测没等到。

### 8.2 真实利用链（与 backtrace 链无关）

```
stage1  A: 1001 字段（max_input_vars 警告 → headers_sent=1）
           + PHPSESSID=\x00（生成新 id、send_cookie=1）
           + 12MB 字段在 php_session_initialize() 内 OOM
           → reset_id 发 cookie 失败 → send_cookie 残留 1，PS(id) 悬空
        B: 48B 字段 + 79B forge（offset 0x10 写 len=0x1000）
           → php_url_encode 越界读 → Set-Cookie 4096B、98 指针 → chunk base
stage2  B: 16 元素数组字段 → 56B HashTable 页落在悬空 PS(id)
           → ZSTR_LEN 读 nTableSize=16，pDestructor=ZVAL_PTR_DTOR → libphp base
stage3  A/B pads 把悬空 reference 固定到 R0；B 用 55B raw buffer 覆盖 R0-0x10，
        fake HashTable 放在 chunk+0x690d8 的 167B 存活字符串里
        pDestructor = zif_system → 命令执行（无需 libc）
```

### 8.3 之前为什么失败（复盘）

1. **我们把 `max_input_vars` 调高**（100000）→ A 的 reset_id 成功、cookie 发出、`send_cookie=0` → B 不再发 cookie，leak 断掉；
2. 我们的 A 用"大字段"OOM（在 multipart 解析里），而不是**在 `php_session_initialize()` 内部 OOM** → `PS(id)`/`send_cookie` 残留状态不同；
3. 我们追的是 backtrace 消费链（那条确实只到 DoS），没按 repo 的 stage 编排（56B raw buffer、167B carrier、pad 数）做。

### 8.4 结论修正

| 旧结论 | 新结论 |
|---|---|
| 官方默认配置只能 DoS | **错。纯 HTTP RCE 在 8.4.26 与 8.5.11 上均可复现**（mod_php，需 display_errors=On、memory_limit 可被 12MB 字段打穿、max_input_vars=1000、单 worker） |
| 没有地址 leak | **错。stage1 Set-Cookie 越界读直接给出 chunk base；stage2 给出 libphp base** |
| leak 需要 lab 辅助 | **部分错。运行时 base 全靠 leak；只有静态符号偏移需按 build 读取（官方镜像可直接用 nm）** |
| FPM 不可打 | 官方称 FPM 经应用层路径可 RCE（本 PoC 是 mod_php 链，FPM 链另需应用条件） |

---

## 9. 默认配置（memory_limit=128M / post_max_size=8M）下的 RCE 实测（2026-10-22）

### 9.1 环境

`php:8.4.26-apache` **不加任何 php.ini**（纯默认）：
`display_errors=1`、`memory_limit=128M`、`post_max_size=8M`、`max_input_vars=1000`、
`session.upload_progress.enabled=1`、MPM prefork（默认 StartServers=5 / MaxRequestWorkers=150）。

### 9.2 post_max_size 绕过（实测）

| 请求 | 结果 |
|---|---|
| 12MB，带 `Content-Length` | `POST Content-Length of 12583036 bytes exceeds the limit of 8388608 bytes`，`$_POST` 为空 |
| 12MB，**chunked（无 Content-Length）** | **被接受**：`n=2`、`biglen=12582912`、peak=41MB |
| 140MB，chunked | `Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 65016420/98566346 bytes)` |

即 advisory 所述"没有可用 Content-Length 的 multipart 请求可绕过 post_max_size"在
Apache mod_php 上成立。

### 9.3 全链复现（单 worker）

把 PoC 的发送端改为 >8MB 自动 chunked、`--huge-mb 140`：

```
[+] chunk base = 0x7fcda8800000
[+] libphp base = 0x7fcdaa473000
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**默认 128M + 默认 post_max_size=8M 下，纯 HTTP RCE 成立。**

### 9.4 多 worker（默认 5/150）

| 阶段 | 结果 |
|---|---|
| stage1 堆泄漏 | ✅ 成功（chunk base=0x7f6567000000） |
| stage2 libphp 泄漏 | ❌ 3 次全失败 |

原因：A/B 两次请求被不同 worker 处理，各自堆独立、chunk base 不同。
真实攻击需要把请求**钉到同一 worker**（keep-alive 长连接 / 反复重试 / 逐 worker 打），
PoC 的"轮换 worker"逻辑假设单 worker。

### 9.5 结论

- 默认 `memory_limit=128M` + 默认 `post_max_size=8M`：**可打**（chunked 绕过 + 140MB 字段）；
- 默认多 worker：stage1 可打，stage2 需要 worker 固定（keep-alive 或重试）；
- 因此"默认配置 RCE"成立，攻击者只需控制请求形状（无 Content-Length + 按 limit 放大字段）。

---

## 10. PHP 7.4.21 分析（2026-10-22）

### 10.1 源码结论

| 项 | 7.4.21 |
|---|---|
| `_zend_hash_str_add_or_update_i` 先加计数后分配 key | ✅ 有缺陷（与 8.x 相同模式） |
| `php_session_reset_id` 发送失败后清零 `send_cookie` | ✅ `php_session_send_cookie(); PS(send_cookie)=0;`（**无条件**） |
| upload-progress 回调前置条件 | **`FILE_START` 前有 `if (!Z_TYPE(progress->sid) \|\| !progress->key.s) break;`** → 没有合法 PHPSESSID cookie 时**根本不做 session 初始化** |
| 有 cookie 时 | `php_rinit_session(0); PS(id)=zend_string_init(sid); PS(send_cookie)=0;` → 不会走 `url_encode` 发送路径 |

**结论**：8.x 的 "悬空 PS(id) + Set-Cookie 越界读" 链在 7.4 上**结构上不存在**（既没有 send_cookie=1 的残留，也没有无 cookie 时的初始化）。7.4 的 RCE 只能走 CVE-2026-109618 的 hash-table 链。

### 10.2 实测（gdb + 扫参）

- `php_session_reset_id` 断点：**未命中**（session 初始化没发生，与 10.1 的 sid 前置条件一致）；
- `zend_hash_str_update`（len>1MB）断点：**未命中**——OOM 发生在解析器的名字/值拷贝（`php_ap_getword`/`substring_conf`/`estrdup`），还没走到插入；
- 扫参结果：`tried to allocate` 恒为解析器缓冲尺寸（12288 / 266240 / 1052672 / 6296371），**从未出现 key 分配（name_len+25）的尺寸**；
- 7.4 的 `memory_get_peak_usage` 与 8.x 差异明显（1000×8KB 字段 peak 仅 4MB），不能用 8.x 经验推算临界。

### 10.3 7.4 的下一步

1. 用 gdb 在 `_emalloc` 上记录**全部**分配尺寸与调用点，画出"名字拷贝成功→key 拷贝失败"的余量窗口；
2. 给请求带合法 `Cookie: PHPSESSID=<32hex>`，让 upload-progress 回调真正进入 session 初始化（此时 `send_cookie=0`，需要另找残留点）；
3. 或改用嵌套数组 + 小值字段，让插入期的小分配（几十字节）成为失败点，直接观察 `tried` 是否落到 26–120 区间。

---

## 11. PHP 7.4.21 泄漏专项扫描（2026-10-22）

### 11.1 错误/警告路径（11 条）

`unserialize`（截断/畸形）、`json_decode`、`preg_match /u`、`gzuncompress`、`iconv`、
`simplexml`、`unpack`、`mb_convert_encoding`、`phar://`、`spl_object_hash`、`debug_zval_dump`：
**全部只输出偏移/行列/输入文本/refcount，无堆地址**。
`spl_object_hash` 在 7.4 是 handle 派生（`00000000XXXXXXXX`），不是对象指针。

### 11.2 扩展级 OOB 读（默认扩展）

`mb_convert_encoding`（UTF-8/UTF-16/SJIS 非法序列）、`iconv`、`finfo_buffer`（随机/畸形 PNG）、
`Phar`、`DOMDocument`：返回值均为安全替换或 false，**没有把堆字节带进响应**。

### 11.3 结构性结论

7.4 没有通用 in-band 泄漏：
- session Set-Cookie 越界读需要 8.x 语义（悬空 PS(id) + send_cookie 残留），7.4 双重封死；
- backtrace 消费链是 8.5 专属；
- 错误消息/序列化/反射/调试函数均不输出地址；
- 扩展级 OOB 读需要"应用调用该函数并回显"，不是通用路径。

因此 7.4 的 hash-table 链卡在 `val.ptr` 需要绝对地址这一步——**缺的是泄漏原语，不是触发参数**。

### 11.4 若要继续 7.4

1. 找应用层信息泄漏（回显 $_SESSION / 序列化数据 / 文件读）；
2. 或找 7.4 的 OOB-read 类 CVE（exif/gd 未装，mbstring/fileinfo 当前版本未见可回显的 OOB）；
3. 已有触发点：name=2,094,000、delta=32、跨请求 256B 复用（lab: t7421g、/root/recal2.py）。
