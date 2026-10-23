# pwdvault —— 能放心丢进网盘的密码库

一个本地优先、零知识的明文信息管理器。**密文可以放在任何网盘上，密钥永远不离开你的电脑。**

它解决的是一对矛盾：明文放本地怕丢，放网盘怕被看。答案是——加密后放网盘：
网盘只看到密文（不怕被看），云端多一份副本（不怕硬盘坏）。

---

> **第一次用？看 [`docs/USAGE.md`](docs/USAGE.md)** —— 从双击到「让 AI 帮你取密码」，
> **全程零命令行**。本文档是命令与技术细节的参考。

## 快速开始：双击就行

**不需要敲任何命令。** 在项目目录里双击下面两个之一（任选一个，不用都双击）：

| 双击这个 | 会发生什么 |
|---|---|
| `start-pwdvault.bat` | 起本地服务 + 自动打开浏览器。有一个黑色窗口显示日志，**关掉它就停** |
| `start-pwdvault.vbs` | 完全一样，但**没有任何窗口**，服务在后台跑（要停得去任务管理器） |

浏览器会打开 `http://127.0.0.1:8765/`。第一次进去直接是**建库向导** ——
设主密码、抄下恢复码，跟着做完就有了一个密码库。之后每次双击都能直接用。

前提：装了 Python 3.10 以上（推荐 3.11），外加 `cryptography`、`argon2-cffi`。
启动器会自己找 Python，找不到会明确告诉你。

> 端口 8765 被占会自动顺延，以窗口里打印的那行为准。
> 想手动起服务，见下面的「命令行入口」一节。

---

## 三条最重要的规则

1. **恢复码用纸抄下来，别放在同一个网盘里。** 忘记主密码时它是唯一出路，程序里查不到。
2. **主密码要够长。** 文件在网盘上意味着攻击者可以离线无限次尝试。5~6 个随机词
   （如「橘子 铁路 钢琴 沙漠 灯塔 钥匙」）是安全线；6 位数字几秒钟就被破。
3. **至少留两份副本。** 网盘防硬盘损坏，防不了误删、账号被封和勒索软件。再加一块
   离线 U 盘，每月同步一次。

---

## 命令一览

| 命令 | 作用 |
|---|---|
| `pv init` | 创建 vault，设置主密码，输出恢复码 |
| `pv add` | 新增一条（无参数时逐项交互） |
| `pv find <关键词>` | 模糊搜索标题/账号/网址/备注/标签/自定义字段 |
| `pv list` | 列出全部（不含密码） |
| `pv show <id> [--reveal]` | 查看一条，密码默认打码 |
| `pv copy <id>` | 复制密码到剪贴板，超时自动清空 |
| `pv copy <id> --field 手机号` | 复制任意字段 |
| `pv totp <id>` | 输出 6 位动态验证码 |
| `pv edit <id> -p 新密码` | 修改，字段不存在会自动新建 |
| `pv rm <id> --yes` | 删除 |
| `pv import 文件 [--dry-run]` | 批量导入 JSON / CSV / TXT |
| `pv export --yes -o 备份.json` | 导出明文（用完请删） |
| `pv passwd` | 更换主密码（只重包密钥，不重加密数据） |
| `pv recovery --reset` | 重新生成恢复码（旧码立即失效） |
| `pv local-unlock on\|off\|status` | 本机免密开关 |
| `pv doctor` | 文件状态、快照、健康度、备份提醒 |
| `pv web` | 打开本地网页界面（只监听 127.0.0.1） |
| `pv mcp` | 以 MCP 服务方式运行（给 Claude Desktop 等客户端用） |

搜索支持字段限定：`pv find tag:购物`、`pv find user:zhangsan`、`pv find title:京`。

---

## 命令行入口

日常使用不需要看这一节 —— 双击 `start-pwdvault.bat` 就够了。这里是给
想排障、想写脚本、或者不想用启动器的人留的。

```bat
:: 浏览器界面：默认自动开浏览器，端口 8765 被占用会自动顺延
:: 这就是启动器双击后实际跑的那条
pv web
pv web --port 9000 --no-browser

:: MCP 服务：stdout 是协议通道，日志全部走 stderr
pv mcp
pv mcp --vault D:\另一个库\data.enc
```

`pv web` 启动后会在 vault 同级目录写一个 `runtime.json`（含端口与一次性 token，
文件权限尽量收到 0600），**正常退出时会删掉**。如果进程被强杀，这个文件会残留，
下次启动覆盖它即可 —— 真实的连接安全靠「只监听 127.0.0.1」+ 每次启动新 token。

`pv mcp` 的用户前提是「已启用本机免密」或客户端配置里带了 `PV_MASTER_PASSWORD`：
stdio 下 stdin 是协议通道，**不能**用它来交互输主密码。

---

## 从一堆明文资料导入（agent 工作流）

这是本工具的重点场景。推荐两条路，可靠性从高到低：

### 路线 A：让 agent 整理成 JSON（推荐）

把乱七八糟的 txt 交给 agent，说「整理成 pwdvault 的 JSON 格式」，得到：

```json
{
  "records": [
    {
      "title": "淘宝",
      "username": "zhangsan@example.com",
      "password": "Tb#2024xy",
      "url": "https://taobao.com",
      "tags": ["购物", "常用"],
      "totp": "JBSWY3DPEHPK3PXP",
      "密保问题": "母亲的名字",
      "绑定手机": "13800138000"
    }
  ]
}
```

任何不认识的键都会原样存进自定义字段，不会被丢弃——这就是「自由」的含义。

```bat
pv --password-stdin import data.json --dry-run   :: 先看
pv --password-stdin import data.json             :: 再存
```

### 路线 B：直接扔 TXT 进去（启发式）

支持三种常见写法，自动识别：

```
淘宝                       知乎 | zhihu_user | Zh#2021       站点    账号      密码
账号: zhangsan             GitHub<TAB>gh_user<TAB>Gh@pass     淘宝    u1        p1
密码: Tb#2024              ...
```

```bat
pv import 我的密码.txt --dry-run     :: 必须预演，看清楚再落库
```

TXT 解析永远不可能 100% 准确，**所以务必先 `--dry-run`**。

### 去重与合并

`--mode skip`（默认，已存在就跳过）／`update`（已存在则更新密码等）／`append`（一律新增）。
去重键是「标题 + 账号」。

---

## 接入 AI：让 agent 自己取密码（MCP）

接好之后，你直接对 agent 说「把淘宝的密码复制到剪贴板」「GitHub 那个账号的用户名是什么」「网易的验证码多少」，它自己调本机密码库拿结果——不用你打开界面，也不用你把密码念出来。

**前提（两条，缺一不可）：**

1. 已经建过库。
2. **开着本机免密**（设置页 → 安全 → 本机免密）。原因：agent 的 stdin 被 MCP 协议占着，
   弹不出输密码的提示框，所以它必须能自己解锁。「我只在网页里解锁过」**不算**——
   网页和 agent 是两个独立进程，各持一份密钥，网页解锁不会让 agent 那边也能用。

**三步：**

1. 打开 Web 界面 → 设置 →「接入 Agent（MCP）」→ 点**复制配置**。
   那段 JSON 是服务端按你这台机器现算的（Python 路径、`pv.py` 路径、库文件路径都取自当前环境），
   **别手抄**——手抄最容易错在盘符和目录上。
2. 粘进 AI 客户端的配置文件（已有别的连接器就并列加一项，不要覆盖）：

   | 客户端 | 配置文件 |
   |---|---|
   | WorkBuddy | `~/.workbuddy/mcp.json` 的 `mcpServers` 段 |
   | Claude Desktop | `claude_desktop_config.json` 的 `mcpServers` 段 |

3. **重启客户端。** MCP 配置文件**不热重载**——保存完不重启，连接器页面什么都不会变。
   重启后看到 `pwdvault` 这个连接器、且有 10 个工具，就成了。

长这样（三个路径按你机器上的真实值）：

```json
{
  "mcpServers": {
    "pwdvault": {
      "command": "C:\\Users\\你\\...\\python.exe",
      "args": ["<项目目录>\\pv.py", "mcp"],
      "env": { "PV_VAULT": "<库目录>\\data.enc" }
    }
  }
}
```

> `env` 里只有 `PV_VAULT` 一项就够，它决定 agent 操作**哪一个**库文件。
> 写成绝对路径；用相对路径的话，MCP 进程的工作目录由客户端决定，会指到别处。

**agent 拿到的是 10 个工具**：搜索、读记录、复制到剪贴板（带自动清空）、算 TOTP 动态验证码、
列暂存区批次等。完整说明见 [`docs/MCP-SETUP.md`](docs/MCP-SETUP.md)。

> **agent 没有落库权限。** `vault_staging_commit` 这类「提交入库」的工具**故意不存在**——
> 入库是不可逆动作，必须你在网页上点确认。这是设计，不是没做完。

---

## 给 agent / 脚本调用（命令行方式）

所有命令都支持 `--json`，输出结构化结果。鉴权有四种方式：

```bat
:: 1. 环境变量（不占用 stdin，最方便）
set PV_MASTER_PASSWORD=你的主密码
pv --json find 淘宝

:: 2. 管道喂密码（一次一行）
echo 你的主密码 | pv --password-stdin --json list

:: 3. 本机免密（一次开启，之后不用密码）
pv local-unlock on
pv --json list

:: 4. 恢复码（忘了密码时唯一的出路）
set PV_RECOVERY_CODE=VY2I-KIEA-6TZO-...
pv --json list
```

典型 agent 流程：

```bat
:: 第一步：预演，让用户确认解析结果
pv --json import tmp.json --dry-run

:: 第二步：确认后落库
pv --json import tmp.json --mode skip
```

> 注意：`--json` 输出中的密码默认是掩码。需要明文时加 `--reveal`，
> 但**不要把 `--reveal` 的结果写进日志或聊天记录**。

---

## 把 vault 放到网盘

程序**不集成任何网盘 API**，你只需要把 `data.enc` 放进同步目录：

```bat
:: 方案一：直接指到网盘目录
pv --vault "C:\Users\你\OneDrive\pwdvault\data.enc" init

:: 方案二：用环境变量固定下来
set PV_VAULT=C:\Users\你\坚果云\pwdvault\data.enc
```

同目录下的 `snapshots/` 会跟着一起同步——这是有意的：网盘上的历史版本能救「改错了」。

同步冲突怎么办？因为只有你一个人用、且每次都是整体原子覆盖，冲突概率很低。
万一出现 `data (1).enc` 这类副本，用 `pv doctor` 看修订号，选大的那个。

---

## 安全模型

**能防住：**

- 网盘服务商、审核系统看到你的内容 —— 他们只有密文
- 网盘账号被盗、文件被批量拖走 —— 没有主密码等于一堆随机字节
- 文件被篡改 —— AEAD 认证会直接报错，不会静默读出脏数据
- 换机器/重装系统后恢复 —— 主密码和恢复码都能在任意机器解开

**防不住：**

- 电脑中木马、键盘记录 —— 所有密码管理器都防不住
- 拿到你解密后的截图或 `--reveal` 输出
- 弱主密码被离线暴力破解（这是唯一真正的短板，请用词组）

**本机免密的取舍：** DPAPI 绑定的是「用户身份」而非「你本人」。开启后，这台电脑上
以你账户运行的**任何程序**都能解密 vault。它防「文件被拷走」，不防「本机已中招」。
所以主密码包裹永远保留，DPAPI 只是便利层。不放心就 `pv local-unlock off`。

---

## 技术实现

| 环节 | 选择 | 理由 |
|---|---|---|
| 密钥派生 | Argon2id（64 MiB / 3 轮 / 4 并行） | 抗 GPU 与 ASIC 暴力破解 |
| 加密 | ChaCha20-Poly1305 | AEAD，加密同时认证，篡改必被发现 |
| 密钥结构 | 主密码 → KEK → 包裹随机 DEK | 改密码只重包一次，不重加密全部数据 |
| 上下文绑定 | 所有 AAD 绑定 `vault_id + 用途` | 密文无法跨 vault 或跨用途搬运 |
| 落盘 | 临时文件 + fsync + 原子 rename | 断电或同步中断不会留下半截文件 |
| 历史版本 | 每次保存前自动快照，保留 30 份 | 「改错了」有退路 |
| 恢复 | 32 字节恢复码，独立 salt | 换主密码不影响恢复码 |

文件结构（`data.enc` 外层是 JSON，便于排查；正文全密文）：

```
format/version/vault_id
kdf        argon2id 参数 + salt
wraps      password / recovery / dpapi 三份「包裹好的 DEK」
payload    加密后的全部记录
meta       创建/更新时间、修订号、条数
```

---

## 故障处理

| 现象 | 处理 |
|---|---|
| 忘记主密码 | 用恢复码：`set PV_RECOVERY_CODE=纸上的码` 后可直接读取和改密码 |
| 文件损坏 | 从 `snapshots/` 挑最近的快照，复制成 `data.enc` |
| 换电脑后本机免密失效 | 正常，用主密码即可 |
| 提示「口令错误或文件已被篡改」 | 两者无法区分。先确认密码，再检查文件大小是否正常 |
| 误删了记录 | 用快照恢复：`copy snapshots\data-20261023-052232.enc data.enc` |

**忘记主密码的完整救急流程：**

```bat
set PV_RECOVERY_CODE=VY2I-KIEA-6TZO-H4SJ-...
pv list                     :: 先用恢复码确认能读到数据
pv --password-stdin passwd  :: 管道给一行新主密码，直接换掉
:: 恢复码保持有效，可以继续留着当备份
```

恢复码用环境变量传而不是命令行参数，是为了避免留在命令历史里。

---

## 开发

```
pwdvault/
  crypto.py     加密原语（唯一碰加密库的地方）
  dpapi.py      Windows 本机绑定
  vault.py      文件格式、原子写、快照
  models.py     记录模型与字段归一化
  importers.py  JSON / CSV / TXT 解析
  service.py    搜索、合并、TOTP、体检
  cli.py        参数解析与输出
tests/          69 个单元测试，含 RFC 6238 官方向量
```

```bat
python -m unittest discover -s tests
```
