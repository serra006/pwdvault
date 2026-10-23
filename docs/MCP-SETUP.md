# 把 pwdvault 接入 MCP 客户端（WorkBuddy / deepseek-harness）

**能干什么**：接好之后，你直接对 agent 说「把淘宝的密码复制到剪贴板」「帮我看下 GitHub 那个账号的用户名」「网易的验证码多少」，agent 自己调本机密码库拿结果——不用你打开界面、不用你说出密码。

**前提**：① 已经 `pv init` 建过库；② **MCP 侧能自己解锁**——在这台机器上跑一次 `pv local-unlock on` 启用本机免密（推荐）。注意「我只在 Web 界面解锁过」**不算**前提满足：两个进程各有各的密钥，界面解锁不会让 agent 直接可用（见第五节）；③ 客户端支持 stdio 类型的 MCP 连接器。

**大概几步**：打开 Web 界面 → 在「接入 MCP 客户端」那块复制它生成的 JSON → 粘进客户端配置文件 → **重启客户端** → 连接器里看到 `pwdvault` 且有 10 个工具。全程大约 2 分钟，唯一的手工步骤是「粘贴 JSON」，因为 MCP 客户端只认配置文件。

> 配置不要手抄。界面上那一段是**按你这台机器现算的**（Python 路径、`pv.py` 路径、库文件路径都取自当前环境），手抄很容易抄错盘符或写错目录。界面入口还没上线的版本，可以用下面的示例照填，把三个路径换成你机器上的真实值。

---

## 一、WorkBuddy

配置文件：`~/.workbuddy/mcp.json`（Windows 上是 `C:\Users\<你>\.workbuddy\mcp.json`）。把下面这段放进 `mcpServers` 里（已有别的连接器就并列加一项，不要覆盖）：

```json
{
  "mcpServers": {
    "pwdvault": {
      "command": "C:\\Users\\se\\AppData\\Local\\Programs\\Python\\Python311\\python.exe",
      "args": ["G:\\deepseek\\pwdvault\\pv.py", "mcp"],
      "env": {
        "PV_VAULT": "G:\\deepseek\\pwdvault\\data.enc"
      }
    }
  }
}
```

粘好之后两件事，缺一不可：

1. **重启 WorkBuddy 客户端**。`~/.workbuddy/mcp.json` **不热重载**——保存文件后不重启，连接器页面里什么都不会变，工具数量也不会变。**「改完工具数没变」= 就是没生效，先重启再怀疑配置。**
2. 打开连接器管理页，右上角「自定义连接器」里找到 `pwdvault`，点**「信任」**。不点信任，工具列表能读出来但调用会被客户端拦下。

> 四个字段的含义：`command` 是解释器的**绝对**路径（写相对命令 `python` 会在某些客户端里找不到解释器，见「常见误改」）；`args` 是「`pv.py` 的**绝对**路径 + `mcp` 子命令」，等价于在命令行里跑 `pv mcp`——直接跑脚本，Python 会从脚本所在目录开始找包，所以**不需要 `PYTHONPATH`**，也不受客户端工作目录影响；`env.PV_VAULT` 见下面一段。整个 `env` 只有这一项就够。

### `PV_VAULT` 决定 agent 操作哪个库

`env.PV_VAULT` 是这个连接器和**哪一个密码库文件**之间的唯一联系。它决定 agent 能搜到、能复制、能改的是哪个库里的记录——不是「界面上当前打开的那个」，而是这个路径指向的那一个。

所以：

- **你有多个库时（比如以后想做工作/个人分离）**，改这一个值就能切换：复制一份配置、把 `pwdvault` 改成 `pwdvault-work` / `pwdvault-personal`，各自指向各自的 `data.enc`，客户端里就会出现两个连接器。两个库互不可见，agent 也不会「串库」。
- **改完必须重启客户端**（同一个理由：配置不热重载）。
- 两个客户端（WorkBuddy / deepseek-harness）如果同时接，建议 `PV_VAULT` 填成同一个值，否则会出现「在 A 里刚存的，在 B 里搜不到」——那不是丢数据，是**两个库**。
- 写成**绝对路径**，不要写 `data.enc` 这种相对路径：MCP 进程的工作目录由客户端决定，相对路径会指到别处（表现为「库是空的」或 `vault_not_found`）。

---

## 二、deepseek-harness

deepseek-harness 的 MCP 配置段是 **stdio 类型**，所以给的是带 `mcpServers` 外层的一整段，直接贴进它的 MCP 配置段即可：

```json
{
  "mcpServers": {
    "pwdvault": {
      "command": "C:\\Users\\se\\AppData\\Local\\Programs\\Python\\Python311\\python.exe",
      "args": ["G:\\deepseek\\pwdvault\\pv.py", "mcp"],
      "env": {
        "PV_VAULT": "G:\\deepseek\\pwdvault\\data.enc"
      }
    }
  }
}
```

它和 WorkBuddy 那份**内容完全一样**，只是外层包装不同（WorkBuddy 的 `config` 已经是 `mcpServers` 里面的一项）。同样是 stdio：harness 负责在本地拉起进程，用 stdin/stdout 走 JSON-RPC，没有端口、没有网络监听，也没有任何后端服务。

改完配置后同样**重启 harness**。判断标准一致：工具数量变了才算生效。

---

## 三、10 个工具能干什么

| 工具 | 什么时候用 | 入参 | 返回什么 |
| --- | --- | --- | --- |
| `vault_status` | 想先确认库可用 / 用户问「库里有几条」「锁着吗」 | 无 | `exists`、`unlocked`、`count`、`revision`、`auto_lock_in_seconds`、`pending_staging`、`inbox_pending`、`unlocked_by`、必要时 `hint`。**永远不会失败**，锁着也回答 |
| `vault_search` | 用户说的站点不确定是哪一条，先定位 | `query`（必填，支持 `tag:` / `user:` / `title:` 前缀）、`limit`（默认 10，上限 50） | `count` + `records[]`，每条只有 `id/title/username/url/tags/has_password/has_totp/secret_field_names/updated`。**不含任何密码值** |
| `vault_get` | 用户想「看」这条的账号、网址、备注、有哪些自定义字段 | `id` 或 `query`（二选一，都给以 `id` 为准） | 脱敏详情：`notes`、自定义字段（敏感值恒为掩码）、`password`/`totp` 为 `••••`、`secret_field_names` |
| `vault_copy` | 用户要「用」密码/账号/网址/动态码登录某个站点 | `id` 或 `query`，`field`（默认 `password`，也可以是 `username`/`url`/`totp`/自定义字段名） | 回执：`copied`（成功时恒为 `true`）+ `title`/`field`/`host`；`auto_clear_in`（30 秒后自动清空，说明定时器装上了）或 `auto_clear: false` + `hint`（**装上了复制、但没装上定时器**——仍算成功，只是要提醒用户手动覆盖剪贴板）。复制本身失败不会给你 `copied: false`，而是直接返回**错误帧**（`isError: true`）。**不含明文** |
| `vault_totp` | 用户要「现在这个验证码」 | `id` 或 `query` | `code`（6 位）、`remaining_seconds`、`title`、`id`。码 30 秒一变 |
| `vault_staging_list` | 用户说「有文件要整理」「inbox 里还有几批」 | 无 | `count` + `batches[]`：`id/source_file/status/item_count/origin/age_seconds`。**不含正文与草稿** |
| `vault_staging_claim` | 准备把某批原文归纳成记录 | `batch_id`（必填）、`lease_seconds`（默认 180，上限 600） | `raw_text`（源文件原文）、`local_draft[]`（本地已解析的草稿，密码掩码）、`warnings[]`、`next_step`。同批次重复认领返回 `staging_busy` |
| `vault_staging_submit` | 归纳完，把草稿交回批次 | `batch_id`、`records[]`（每条 `title/username/password/url/notes/totp/tags/自定义字段`）、`summary`（可选，≤200 字） | `status`（→`review`）、`accepted`、`item_count`、`warnings_by_item[]`。**只写草稿，不落库** |
| `vault_add` | 用户口述了一条新密码要存 | `record`（必填）、`dry_run`（**默认 true**） | `dry_run`、`created`、`id`、`revision`、`count`、`warnings[]`。默认一个字节都不写库，用户确认后才传 `dry_run: false` |
| `vault_update` | 用户要改一条记录（换密码、补网址、加备注） | `id`、`changes`（`{字段名: 新值}`）、`expected_updated`（**必填**，乐观锁） | 成功 `updated/id/revision/count`；时间戳过期返回 `isError` + `code=record_conflict`，**盘上一个字节都没覆盖** |

### 对 agent 说人话的例子（照抄就能用）

- `vault_status`：「密码库现在锁着吗？里面有几条？」
- `vault_search`：「我好像存过淘宝的账号，是哪一条？」
- `vault_get`：「GitHub 那条的网址和备注念给我听（密码不用）。」
- `vault_copy`：「**把淘宝密码复制到剪贴板**，我要去网页上登录。」← 最常用的一条
- `vault_totp`：「网易的验证码现在是多少？」
- `vault_staging_list`：「inbox 里还有几批没整理？」
- `vault_staging_claim`：「认领那一批 8 条的，把原文给我看看。」
- `vault_staging_submit`：「整理好了，按这个草稿交回去，等我确认。」
- `vault_add`：「帮我存一条：招商银行，卡号尾号 8899，密码是刚才那个，先给我看看草稿。」
- `vault_update`：「把淘宝那条的密码换成新的，其它别动。」

---

## 四、四个「不存在」的工具（不是漏了，是故意的）

| 不存在的工具 | 为什么不做 |
| --- | --- |
| `vault_delete` | 删除不可逆。agent 删错一条，用户可能几周后才发现。删除只允许**人**在 Web 界面做，而且要手打标题确认（`confirm_title` 不匹配就取消）。 |
| `vault_change_master_password` | 主密码一改，所有旧密文与恢复码的关系全变；改错了库就打不开。这是**只有人能承担后果**的操作，必须在界面上走「确认旧密码 → 生成新恢复码 → 让用户抄下来」的流程。 |
| `vault_staging_commit` | 批量落库必须人工确认。模型只要幻觉一次（把「验证码」当成密码、把网址截断），就是**一整批脏数据**同时进库，而且 `vault_staging_submit` 交回的草稿看起来完全合理。所以 agent 只能交草稿，入库按钮在人手里。 |
| `vault_import_batch` | 同上：批量导入是「一次写入 N 条」，风险是批量的。单条新增有 `vault_add`（默认 dry_run），够用。 |

反过来说：**agent 有写权限的只有两条路**——`vault_add`（默认试运行）和 `vault_update`（必须带 `expected_updated`，绝不覆盖别人的改动）。批量整理走「认领 → 交草稿 → 人等确认」三段式。

如果 agent 真的去调这四个名字，会得到 JSON-RPC 错误 `-32602 Unknown tool`。**那是预期行为**，不是配置错了，也不是版本旧——不要为了让 agent「能用」去改客户端配置。

---

## 五、解锁链：MCP 进程为什么不能问你要主密码

stdio 类型下 **stdin 被 JSON-RPC 协议独占**，任何 `input()` / `getpass()` 都会把提示写进 stdout（直接毁掉协议）并吞掉下一条消息。所以 `pwdvault` 的 MCP 进程**绝不交互式读密码**，只按下面的顺序尝试，全失败就如实返回 `code=locked`：

1. **本机免密（DPAPI）** —— 你自己跑一次 `pv local-unlock on`，之后同一台机器、同一个 Windows 用户下，MCP 进程能自动解锁。密钥由 Windows DPAPI 保管，落盘的只有密文。**这是推荐做法。**
2. **环境变量 `PV_MASTER_PASSWORD`** —— 客户端配置里可以写，但**不建议**：那等于把主密码明文存进 `mcp.json`，任何能读这个文件的进程（同步盘、备份、别的 agent）都能拿走。
3. **都没有 → 返回 `locked`**，`hint` 会提示去启用本机免密。**别把 `hint` 里的「先在 Web 界面解锁」当成对 MCP 有效的办法**——它对 MCP 进程没有作用（两个进程的解锁状态不共享，见下面一节）。

### 关于「界面已经解锁了，Agent 还要再解锁一次」

会。**Web 界面与 MCP 进程是两个独立进程，各自持有一份密钥，解锁状态不共享。**
MCP 进程按上面的链自己解锁：本机免密 → `PV_MASTER_PASSWORD` → 返回 `locked`。

所以日常最省事的做法是在这台机器上启用一次本机免密：

```bat
pv local-unlock on
```

之后 Web 和 MCP 都不需要再输密码。若不想开本机免密，也可以在客户端配置的 `env` 里写
`PV_MASTER_PASSWORD`——代价是主密码以明文存在客户端配置文件里，自己权衡（本机和这个
文件谁能读，就等于谁能读你的库；见第七节安全边界）。

> 「MCP 把调用转发给 Web 进程（单写者、单份 DEK）」是**规划中的能力，本版本未实现**。
> 所以现在没有任何「在界面上解锁一次，agent 就自动能用」的捷径：不要依赖它。

---

## 六、排查表

| 现象 | 最可能的原因 | 怎么办 |
| --- | --- | --- |
| 客户端里看不到 `pwdvault`，或看到但**工具数是 0** | ① 改完配置没重启；② `args[0]`（`pv.py` 的路径）写错，或项目目录被移动过；③ `command` 路径不对 | 先重启客户端；仍为 0 就在终端手跑配置里的那条命令（`"<command>" "<pv.py 路径>" mcp`），能握上手说明配置对、问题在客户端没重载；报 `can't open file ...pv.py` 就是 `args[0]` 的问题；报 `No module named 'pwdvault'`/`invalid choice: 'mcp'` 说明跑错了脚本（不是本项目的 `pv.py`，或版本太旧） |
| 工具报 `locked` | 库锁着，且既没启用本机免密也没有可用解锁路径。**注意：Web 界面解锁不会让 agent 也能用**（两个进程各有各的密钥，不共享） | 跑一次 `pv local-unlock on`（推荐），或在客户端 `env` 里设 `PV_MASTER_PASSWORD`（不推荐，见第五节）。**只解锁界面是没用的** |
| 工具报 `vault_not_found` | `PV_VAULT` 指向的文件不存在 | 先 `pv init` 建库，或把 `PV_VAULT` 改成真实的库文件路径 |
| 工具报 `auth_failed` / 提示环境变量里的主密码不对 | 配置里写了 `PV_MASTER_PASSWORD` 但值不对（换过主密码） | **删掉那个环境变量**，改用 `pv local-unlock on` |
| `vault_copy` 说 `copied: true`，但剪贴板没变 | ① **agent/MCP 进程不在你正用的这台机器上**（容器、远程主机、WSL）——值确实写好了，只是写在**那台机器**的剪贴板；② 剪贴板被别的程序占用或无桌面会话 | 先看回执的 `host` 字段：**不是本机就属于第 ① 种**（见第八节第 1 条，这**不是失败**）。第 ② 种不会给你 `copied: true` 的回执，而是直接返回**错误帧**（`isError: true`，通常是 `internal error` / `-32603`，因为 Windows 剪贴板被独占时底层会抛错）——所以「有没有复制成功」只看 `copied` 与是否收到错误帧，别把 `auto_clear: false` 当成失败 |
| 回执里是 `auto_clear: false` + `hint` | **复制成功，只是没装上自动清空定时器**（30 秒清空这件事没成立） | 这不是失败：`copied` 仍是 `true`，值就在剪贴板里。按 `hint` 提醒用户用完手动复制一个无关内容覆盖掉；不要对用户承诺倒计时 |
| 工具报 `ambiguous`（`code=ambiguous_record`） | 关键词命中多条（比如你存了三个「淘宝」） | 看返回的 `candidates`（只有 `id/title/username`），让用户选一条，然后用 `id` 再调一次。**不要让 agent 猜** |
| 工具报 `record_conflict` | 你刚在界面上改过这条，agent 手里的 `updated` 过期了 | 让 agent 重新 `vault_get` 读最新内容再决定，别覆盖 |
| 在 A 客户端刚存的，B 客户端搜不到（或界面里搜不到） | 两边 `env.PV_VAULT` 指向**不同的库文件**（不是丢数据，是两个库） | 对比两处配置的 `PV_VAULT` 与界面用的 `--vault`，统一成同一个绝对路径；见第一节「`PV_VAULT` 决定 agent 操作哪个库」 |
| 工具报 `-32602 Unknown tool` | 工具名拼错，或调了第四节里那四个**故意不存在**的工具 | 这不是配置问题，改用存在的工具；入库/删除/改主密码请在界面上做 |
| 命令直接崩出裸 `RuntimeError`，消息里有「审计枚举配置错误」 | 审计动作名写错——**我们的代码 bug**，不是你的配置问题。正常情况下用户碰不到：审计写入的枚举错误默认不降级，就是为了让它在开发/CI 阶段当场炸，而不是静默丢掉一条审计记录 | 升级到修复版本；临时绕过可设 `PV_AUDIT_STRICT=0`，那样会退化成 stderr 一行 WARNING 并**留下审计空档**，不推荐长期这么跑 |
| 审计日志里缺了某次操作的记录，同时 stderr 有「`审计写入失败`」 | 审计目录不可写：只读盘、权限不足、磁盘满（这是**环境**问题，不是配置问题） | 修好 `%PV_HOME%/logs/` 的权限或磁盘空间。审计写失败**不会**影响工具本身（`vault_get` 之类照常工作），但那段区间的审计是空档，事后补不回来 |

---

## 七、安全边界（一句话记住）

**用户要「用」密码时走 `vault_copy`（值只进剪贴板，不进对话），要「看」时密码永远只显示掩码；任何情况下都不要让 agent 把字段值念进对话。**

加三条配套事实：

- 想让 MCP 免密，**用 `pv local-unlock on`，不要用 `PV_MASTER_PASSWORD`**。原因不是口味问题：把主密码写进客户端配置，等于**库的钥匙以明文躺在磁盘上**，这会抵消整个零知识设计——本来攻击者拿到 `data.enc` 只是一堆密文，现在旁边多了一个装着钥匙的明文文件，同步盘/备份/任何能读 `mcp.json` 的进程都能配成一对。而 `pv local-unlock on` 在这台机器上**严格更优**：密钥由 Windows DPAPI 以你的用户身份保管，落盘的同样只是密文，别的用户和别的机器解不开。只有 DPAPI 不可用（非 Windows、域策略禁用、换了用户身份）时，才退而考虑 `PV_MASTER_PASSWORD`。
- 「把密码复制到剪贴板」不等于「把密码告诉模型」：`vault_copy` 的响应里没有任何明文，agent 拿到的只有回执。
- 审计日志只记「谁、对哪个 id、的哪个字段、做了什么、是否成功」，**永不记录字段值**。文件是**库文件同级的** `logs/audit.jsonl`：库在 `<库目录>\data.enc` 就写在 `<库目录>\logs\audit.jsonl`（默认库是 `~/pwdvault/data.enc`，所以默认路径是 `~/pwdvault/logs/audit.jsonl`）。**换库目录，日志跟着换**——`PV_HOME` 或 `--vault` 改过之后别去老路径找。

---

## 八、已知限制（都是真的边界，先知道能省下半小时排查）

1. **`vault_copy` 写的是「MCP 进程所在那台机器」的剪贴板。** 如果你的 agent 跑在容器、远程主机、WSL 或另一台机器上，密码会被复制到**那台机器**上，你在自己电脑上粘贴不出来——看起来像「复制失败了但其实成功了」。回执里的 `host` 字段就是为了让你察觉这件事：**它的值不是你正在用的那台机器，就别在本机等粘贴。** 这类情况下改用「在跑 agent 的那台机器上直接打开密码库」或者放弃剪贴板/改用人工输入。
2. **`vault_search` 是子串模糊匹配，不是精确匹配。** 搜 `淘宝` 会同时命中「淘宝」和「淘宝联盟」；搜索接口会如实返回多条候选（`count` + `records[]`），**工具不会替你猜哪一条**。接着用 `vault_copy` / `vault_get` 时若关键词仍命中多条，会返回 `code=ambiguous_record` + `candidates`（只有 `id/title/username`），让你反问用户再选。想跳过这一步：先 `vault_search` 拿到 `id`，之后一律用 `id` 调用。
3. **批量整理（`vault_staging_*`）agent 只能提交草稿，落库必须你在 Web 界面确认。** 这是**设计上的安全闸门，不是缺陷**：`vault_staging_submit` 之后批次进入 `review` 状态，agent 的任务到此为止；`vault_staging_commit` 这个工具根本不存在（见第四节）。所以「agent 说整理完了」≠「已经进库了」，你还要去界面上点确认。
4. **MCP 进程空闲 15 分钟会自动丢弃内存里的密钥**，下次调用重新走一遍解锁链（`vault_status` 的 `auto_lock_in_seconds` 就是这条倒计时）。这是故意的：少一个「密钥在内存里放一整夜」的窗口。如果你觉得频繁被锁很烦，正确解法是 `pv local-unlock on`（DPAPI 自动解锁，重走解锁链时你也不会被打断），而不是把超时改长——真需要改可以调 `config.toml` 的 `[mcp] auto_lock_seconds`。
5. **Web 界面与 MCP 进程的解锁状态互相独立，不共享密钥。** 想在两边都免密，请启用本机免密（`pv local-unlock on`）。「MCP 转发给 Web 进程」是规划中的能力，**本版本未实现**——所以「我在界面上解锁过一次了」不会让 agent 直接可用。

---

## 九、常见误改（抄完配置别手痒）

- 把 `args` 只写成 `["mcp"]`：`command` 是 `python.exe` 时，这等于在跑 `python mcp`——**找不到名为 `mcp` 的文件**，客户端表现为「连接器里一个工具都没有」，而且不报错。`mcp` 是 `pv.py` 的子命令，必须写成 `["<pv.py 的绝对路径>", "mcp"]`，两者缺一不可。
- 把 `args[0]` 写成相对路径（`pv.py` 或 `.\pv.py`）：MCP 进程的工作目录由客户端决定，相对路径会指到别处 → `can't open file ...pv.py`。**一定是绝对路径**。
- 移动了 `pv.py` 或整个项目目录却不重新生成配置：`args[0]` 还指着老位置 → 启动即失败。**换目录后回来重新复制一次配置**（这也是为什么配置要由界面生成而不是手抄）。
- 在 `env` 里手加 `PYTHONPATH`：现在不需要它（`pv.py` 自己会把同目录插进 `sys.path`）。加了不会坏，但会掩盖「`args[0]` 指错了目录」这类真问题。
- 把 `command` 改成 `python`（相对命令，靠客户端继承的 `PATH` 去找）：某些客户端拉起子进程时的 `PATH` 和你终端里的不一样，会直接「找不到解释器」；Windows 上还可能命中 Microsoft Store 的 `python.exe` 垫片（App Execution Alias），表现为**进程秒退、工具数 0、还没有任何报错**。**永远写解释器的绝对路径**（就是接口返回的那个 `python` 值）。
- 把 `env` 里的值写成「带引号的字符串」，例如 `"PV_VAULT": "\"C:\\Users\\se\\pwdvault\\data.enc\""`：JSON 里其实已经有一层引号了，多写的这一对会被当成**路径的一部分**，Windows 下于是去找一个名字里带引号的文件 → 报「文件不存在」/`vault_not_found`。**`env` 的值只写裸路径**，前后不要加引号，反斜杠按 JSON 规则写 `\\`。
- 把 `PV_VAULT` 写成相对路径（`data.enc`）：MCP 进程的工作目录由客户端决定，相对路径会指到别处，表现为「库是空的」或 `vault_not_found`。
- 在 `env` 里加 `PV_MASTER_PASSWORD`：见第五节，不推荐。
- 改完不重启：这是**绝大多数「配置不生效」的真因**。
