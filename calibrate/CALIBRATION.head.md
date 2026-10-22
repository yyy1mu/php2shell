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

