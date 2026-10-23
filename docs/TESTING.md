# 测试规范与踩坑记录

面向所有要在这个仓库里跑测试、写测试的人。这里只写**会导致误判**的东西 ——
「看起来是某条用例失败，实际是测试环境或 runner 坏了」这类问题最贵，因为它会让人
去修一份没坏掉的代码。

所有结论分两档，**请按标记区分可信度**：

- **【实测】**：在本机 Python 3.11.9 / Windows 上跑过，附复现方法。
- **【未验证】**：按代码推断，没有实际跑过。不要当依据用。

---

## 一、`UnicodeDecodeError` 截断整个 run（**最重要的一节**）

### 现象

跑了若干个点（`.`)之后，输出里出现一段 `traceback.py` 的栈，末尾是

```
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe6 in position 33: unexpected end of data
```

然后**没有汇总行**（没有 `Ran N tests`、没有 `OK/FAILED`）。这不是某条用例失败 ——
是 `unittest` 的 **runner 自己崩了**，后面没跑到的用例根本没执行。

看到 `_exc_info_to_string` / `addError` 出现在栈里，就能确认是 runner 崩了，
**不要去改业务代码**。

### 机理【实测】

`traceback` 格式化一帧时有两个数据来源，它们在「源码与编译时看到的文本不一致」时会打架：

1. 显示用的**源码行**：从 `linecache` 读**当前磁盘上的文件**；
2. `^^^^` 指示用的**列偏移**：来自**字节码对象**的 `co_positions()`。

Python 3.11 的 `_byte_offset_to_character_offset()` 会执行

```python
return len(as_utf8[:offset + 1].decode("utf-8"))
```

当 `offset + 1` 落在某个多字节字符（中文 UTF-8 占 3 字节）**中间**时，`.decode()` 抛
`UnicodeDecodeError`。

**两个条件必须同时成立**：① 那一行源码里有非 ASCII 字符（本仓库全是中文，几乎必然）；
② 列偏移来自另一份文本。

### 触发它的两种原因 —— 清 `__pycache__` 只能解决第一种

#### (A) 陈旧字节码【实测】

CPython 判定 pyc 是否可用，只比对 pyc 头部记录的 `(源文件 mtime **秒级**, 源文件**字节数**)`。
所以只要「改了一行但**总字节数不变**、且改动发生在**同一秒内**」，校验就会通过、
字节码却是旧的。

在本仓库里这极易发生：改中文注释、`"xxx"` → `"中中中"`、调整空格，都常常保持字节数不变。

#### (B) 并发编辑（**多人协作时这才是主因**）【实测】

`linecache` 是**懒加载**的：模块 import 时并不会把源码读进缓存，直到**第一次要格式化
traceback** 才去读盘。于是：

```
t0  A 的测试进程 import pwdvault/foo.py（编译自文本 V1）
t1  B 保存了对 pwdvault/foo.py 的修改（文本 V2，中文位置变了）
t2  A 的进程里某条用例报错 → 格式化 traceback → 从盘上读到 V2，用 V1 的列偏移去切
t3  整个 run 崩掉
```

**清 `__pycache__` 对这种情况完全无效**，因为根本不存在陈旧字节码。
只要有人在同一条工作树上保存文件，跑全量的那一百秒里随时可能撞上。

复现（不依赖 pyc，隔离变量）：

```python
import importlib, linecache, sys, traceback
sys.path.insert(0, '.')
open('vic.py', 'w', encoding='utf-8').write('def boom():\n    raise IndexError("b")\n')
vic = importlib.import_module('vic')          # 编译自 V1
open('vic.py', 'w', encoding='utf-8').write('def boom():\n    中raise IndexError("b")\n')
try:
    vic.boom()
except IndexError:
    traceback.print_exc()                     # ← 抛 UnicodeDecodeError
```

### 怎么办

**(A) 的解法**：跑之前清一次字节码缓存。三种写法都【实测】可用：

```bash
# ① Git Bash / MSYS（本仓库默认 shell）
find . -name __pycache__ -type d -prune -exec rm -rf {} +
```

```powershell
# ② PowerShell
Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
```

```bash
# ③ 任意 shell（不依赖 find / PowerShell，最稳，推荐写进脚本）
python -c "import pathlib,shutil;[shutil.rmtree(p,ignore_errors=True) for p in sorted(pathlib.Path('.').rglob('__pycache__'),key=lambda x:len(x.parts),reverse=True)]"
```

> 第 ③ 种必须按**路径深度倒序**删除，否则先删父目录会让子目录的 `rmtree` 失败。

**(B) 的解法**：**在一个不会被人改动的工作副本上跑全量**。

```bash
# 推荐：先在临时副本上跑，拿到可信结论
# （Windows 上用 %TEMP%，Git Bash 里用 /tmp —— 换成你自己的临时目录即可）
export COPY="$(cygpath "$LOCALAPPDATA\\Temp" 2>/dev/null || echo /tmp)/pv-verify"
python -c "import os,shutil;shutil.copytree('.', os.environ['COPY'], ignore=shutil.ignore_patterns('__pycache__','snapshots','.git'), dirs_exist_ok=True)"
cd "$COPY" && python -m unittest discover -s tests
```

退一步的最低要求：**跑全量前确认没有别人正在编辑同名文件**，并在结论里注明
「本次 run 期间工作树处于冻结状态」。否则「全绿」这个结论不可信 —— 因为它可能只是
恰好没在崩溃窗口里被格式化。

被截断的 run **不能**当成「部分通过」，它的结论是**零**。

### 能不能用环境变量绕过？——不能

| 手段 | 结论 | 依据 |
|---|---|---|
| `PYTHONUTF8=1` | **无效**【实测】 | 崩溃点是「把源码行切成字节后按列偏移解码」，与 stdout/stdin 编码无关 |
| `PYTHONIOENCODING=utf-8` | **无效**【实测】 | 同上 |
| 两者同时 | **无效**【实测】 | 同上 |
| `PYTHONDONTWRITEBYTECODE=1` | **只阻止「写」，不阻止「读」**【实测】 | 已存在陈旧 pyc 时照样被加载；且对原因 (B) 毫无作用 |

`PYTHONDONTWRITEBYTECODE=1` 仍然值得默认打开（能让原因 (A) 不再**产生**），但它既治不了
已有的陈旧 pyc，也治不了并发编辑，所以**不能拿它替代上面的两条措施**。

---

## 二、编码约定

- **所有 `.py` 必须是 UTF-8（无 BOM）**。仓库现状已全部合规（`pathlib.rglob('*.py')`
  逐个 `decode('utf-8')` 检查通过）。
- 不要用 CP936/GBK 保存源码。一旦有文件不是 UTF-8，`linecache` 读进来的行与字节码
  偏移必然对不上，会退化成第一节那个崩溃。
- 测试里读写文件**永远显式给 `encoding=`**（`write_text(..., encoding="utf-8")`）。
  依赖默认编码的测试在别人机器上会挂。
- 需要在 Windows 控制台里看中文报错时，`chcp 65001` 只影响显示，不影响测试结论。
  输出乱码不是失败，**不要为了让输出好看去改断言**。

---

## 三、时间戳：微秒级，不要按定长解析

`models.now_iso()` 是**微秒精度 + 显式时区**：

```
2026-10-23T09:00:39.123456+00:00     # 新
2026-10-23T09:00:39+00:00            # 旧（v1.0 数据，仍然可读、原样保留）
```

**不要**按定长切片解析（`stamp[:19]`、`len(stamp) == 25`、`stamp[20:26]` 之外的
硬编码位置）—— 新旧两种形态长度不同，定长假设会在第一份旧数据上就炸。

正确做法：`datetime.fromisoformat(stamp)`。两种形态它都吃。

为什么必须是微秒：`locks.VaultStore.commit` 用 `target.updated != expected_updated`
判定 stale，秒级截断会让「同一秒内 读 → 他人写 → 提交」被误判成无冲突，把别人的改动
静默覆盖（lost update）。这是刻意改的格式变更，不是顺手多写几位数字。

> 这是一次 **`data.enc` 落盘格式变更**。任何「只按秒级解析」的下游代码都需要复核。
> 已确认安全的部分：全仓无 `[:19]` 定长切片；快照文件名走独立的
> `strftime("%Y%m%d-%H%M%S")`；`staging` 批次时间戳是毫秒、`audit` 是秒，各自独立
> 命名空间、互不比较。

---

## 四、本仓库测试的固定纪律

### 4.1 每个任务交付前必须跑全量

单模块绿不算完。历史上多次出现「单跑绿、全量红」，原因是**跨用例污染**（共享临时
目录、全局 patch 未还原、类属性被改）与**并发干扰**（子进程压测把机器占满，别的用例
的时序假设失效）。

```bash
# 全量（含变异测试，约 100~130 秒）
python -m unittest discover -s tests
```

赶进度时可以用 `PV_QA_SKIP_MUTATION=1` 跳过变异测试做快速回路，但**提交前必须至少
完整跑一次**。

### 4.2 禁止真 `sleep`

唯一例外：并发测试里那个 300ms 的持锁窗口（`tests/_locker.py` 的 `hold_ms`），
它的目的就是「让另一个进程有机会去抢锁」，没有替代品。

除此之外，任何 `sleep` 都是在赌机器负载，必然在 CI 或别人机器上随机红。

### 4.3 涉及时间的断言必须注入时钟

- `locks` / `staging` 的超时、租约、编辑锁：构造时传 `clock=`；
- `models` 的取时点：`mock.patch("pwdvault.models.utc_now", ...)`。

**只注入时间，不注入格式**。如果把 `now_iso()` 整个换掉，用例就会绕过被测的精度
与序列化逻辑，把缺陷「测成通过」。

### 4.4 外部依赖必须 mock

- **剪贴板**：`pwdvault.clipboard.copy_text` / `copy_with_autoclear` 一律打桩
  （见 `tests/test_service.py::CopyFieldTests`）。真剪贴板会污染跑测试的人正在用的
  机器，在无人值守环境里还会直接抛 `RuntimeError`。
- **DPAPI**：`pwdvault.crypto` 的 dpapi 封装一律打桩。可用/不可用两条分支都要有用例。

### 4.5 并发测试必须用子进程，不能用线程

用线程测「锁」等于没测：线程测到的是本进程里那把 `threading.RLock`，而真正要防的是
**跨进程**互相覆盖。所以：

- 跨进程锁：`tests/_locker.py`（`subprocess` + 独立解释器）；
- 跨进程写不丢：`test_fifty_plus_fifty_no_loss`（50 个子进程 ∥ 50 次进程内提交）；
- 跨进程去重：`test_two_processes_scan_same_file_only_one_batch`。

线程用例仍然要有，但它证明的是「同进程重入不死锁」，**不能**顶替上面的子进程用例。

### 4.6 `expectedFailure` 反转了要处理

`unittest` 对标记为 `@expectedFailure` 但实际通过的用例报 **`UNEXPECTED SUCCESS`**，
并且**计入失败**。这在本仓库很常见：QA 先用 `expectedFailure` 钉住一个缺陷，缺陷修好
之后那条用例就变成 `UNEXPECTED SUCCESS`。

看到它的正确处理是**删掉 `@expectedFailure` 装饰器**（缺陷已修，用例应该转正），
而不是去改断言让它重新失败。

### 4.7 性能用例的失败要看数字，不要先怀疑机器

本仓库的性能用例阈值都放得很宽（例如 inbox 500 个文件的阈值是 30 秒，实测约 5.8 秒）。
一旦真的红了，通常意味着**复杂度退化了**（O(n²) 这类），不是机器慢。历史案例：
`inbox.scan_once` 每建一批就把 staging 目录重扫一遍判重，500 个文件时首轮 34.2 秒。

### 4.8 跑测试用的解释器

```bash
# 用你这台机器上那个能正常启动的 Python 3.9+
python -m unittest discover -s tests
```

用 `python.exe -m unittest`（模块方式），不要用 `python.exe tests/test_x.py`
（`sys.path` 与 `tests/_support.py` 的相对导入会失效）。

### 4.9 并发压测用例必须显式覆写 `[lock] timeout_seconds`

产品默认的锁等待是 **3 秒**（`DEFAULT_LOCK_TIMEOUT_SECONDS`），这个值是给**人手操作**
准备的：用户点一下、等 3 秒还没轮到，就该看到「另一个窗口正在写入」而不是继续卡着。
50 个进程互相抢锁的压力测试完全不是这个场景 —— 在机器忙（同机还跑着变异测试的
子进程）时，3 秒预算会被真实地耗光，于是用例红成一条 `LockTimeout`，
看起来像产品缺陷，其实是**测试给了不合适的预算**。

所以：任何「N 个进程同时写」的用例，**在 `config.toml` 里显式给一个大预算**，
不要依赖产品默认值。`tests/_support.py::write_config` 已经这么做了（写
`timeout_seconds = 20`）；手工写 config 的用例请照抄这条约定。

【实测】`test_locks.CrossProcessWriteTests.test_fifty_plus_fifty_no_loss` 在全量跑
（同机还有多个子进程）时偶发 `LockTimeout: 等了 3 秒还没轮到`；单独跑该模块
21 tests / 5.4 秒全绿。**不改产品默认值**。


---

## 五、「看起来像失败」速查表

| 现象 | 真正的成因 | 处理 |
|---|---|---|
| run 跑到一半没有汇总行，末尾是 `UnicodeDecodeError ... _byte_offset_to_character_offset` | **runner 崩了**（不是用例失败）。原因 A：stale `__pycache__`；原因 B：**跑的时候别人改了源码**（linecache 懒加载） | 见第一节；B 只能在冻结的工作副本上跑 |
| `UNEXPECTED SUCCESS` | 缺陷已修，`@expectedFailure` 标记过期 | 删掉装饰器 |
| 单模块绿、全量红 | 跨用例污染 / 并发干扰 | 用 `-p` 逐模块二分定位污染源 |
| 只测「第 N 次提交之后」的断言随机红 | 依赖墙钟推进或秒级时间戳 | 注入时钟 |
| 剪贴板相关用例在无桌面环境报 `RuntimeError: 打开剪贴板失败` | 没 mock 剪贴板 | 打桩（见 4.4） |
| 锁超时（退出码 11）在压测里偶发 | 50 个进程同步轮询打在同一时刻 | 测试夹具把 `[lock] timeout_seconds` 放宽（`tests/_support.py` 里是 20s），**产品默认值不动** |
| 上一个 run 刚「绿」，立刻重跑就崩 | 两次 run 之间有人保存了文件 | 同上（原因 B） |

---

## 附：测试规模与耗时基线

- 全量：**555 个用例 / 约 165 秒**（含变异测试；数字会随用例增加变化，仅作量级参考）
- 单文件定位失败（推荐先这样二分）：

  ```bash
  python -m unittest discover -s tests -p "test_staging.py" -v
  ```

> 以上数字取自**隔离副本**上的一次完整 run（`2026-10-23T10:41Z` 快照，
> `Ran 555 tests in 164.687s / OK`）。
> 同一天在主工作树上跑同一个全量会在 21~30 秒处崩掉 —— 原因就是第一节的原因 (B)：
> 那次 run 期间有人在改文件。这也是「在副本上跑」这条建议的由来，不是洁癖。
>
> **读任何一个「全绿」结论时都要问一句：它是什么时刻、在哪个工作树上跑出来的。**
> 这个仓库一天内用例数从 198 涨到 555，中间多次「5 分钟前 4 红、5 分钟后全绿」，
> 不带时间戳的结论没有意义。
