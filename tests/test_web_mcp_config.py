"""`GET /api/mcp-config`（MCP 一键接入）的专项测试。

为什么单独一个文件（而不是塞进 `test_web_api.py`）：这个接口的契约是**给用户看的
配置**，与记录 CRUD 的契约是两件事；放在一起会让「一文件两主」——两个人同时在
`test_web_api.py` 里加用例时，搬迁/重命名很容易撞车。

现状说明（避免后人以为漏了）：`test_web_api.py` 里还有 8 条 `McpConfigTests` /
`McpConfigAccessTests`（形状、真路径、工具清单、真子进程握手等）。它们**计划搬迁**
到本文件，但搬迁需要同时改动那个文件，得先和它的 owner 对齐，所以本文件目前只放
本迭代新增的「库文件不存在」这条用例。搬迁完成前**不要**把用例在这里再抄一份，
否则同一断言会跑两遍、改一处忘一处。
"""

from __future__ import annotations

import http.client
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _support as support

from pwdvault.config import Settings
from pwdvault.web.server import TOKEN_HEADER, WebServer

TOKEN = "test-mcp-config-missing-vault"


class McpConfigMissingVaultTests(unittest.TestCase):
    """库文件还不存在时：配置本身仍然有效（200 照给），但 notes 必须让人先去 pv init。

    这条用例守的是一个很容易被「顺手优化」掉的语义：没有库不是配置错误 ——
    用户往往是「先配客户端、再 `pv init` 建库」，此时把接口变成 404 会让他配不完。
    但反过来，配置里给出一个不存在的 `PV_VAULT` 而不提示，用户接完只会看到
    `vault_not_found`，所以 `notes` 必须补一条明确指引。
    """

    def setUp(self) -> None:
        self.home = support.make_home(self)
        # 故意不建库：整条用例的前提就是「路径给了、文件还没有」。
        self.missing = self.home / "not-yet-created.enc"
        settings = Settings(
            vault_path=self.missing,
            inbox_enabled=False,  # 本用例不涉及 inbox，关掉后台线程让结论更干净
        )
        self.assertFalse(settings.vault_path.exists(), "前提被破坏：这个路径不该存在")

        # 参数全部来自 `web/server.py::WebServer.__init__` 的真实签名。
        self.server = WebServer(
            settings,
            port=0,  # 0 = 让系统分配临时端口，避免与并行用例抢端口
            open_browser=False,
            quiet=True,
            token=TOKEN,
            auto_lock_seconds=0,  # 关掉自锁，避免倒计时干扰
            poll_seconds=60.0,
            idle_check_seconds=60.0,
        )
        self.server.start()
        self.thread = self.server.start_in_thread()
        # addCleanup 是**后进先出**：所以先注册 join、后注册 stop，
        # 实际执行顺序是 stop() → join()，与 `test_web.py` 的收尾顺序一致。
        self.addCleanup(self.thread.join, 5.0)
        self.addCleanup(self.server.stop)

    def _get_config(self) -> tuple[int, dict]:
        conn = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=15)
        try:
            conn.request("GET", "/api/mcp-config", headers={TOKEN_HEADER: TOKEN})
            response = conn.getresponse()
            body = response.read()
            # `read()` 已经把响应体读完并缓存在 HTTPResponse 里，所以
            # `close()` 之后继续读 `response.status` 是安全的（值早已解析下来），
            # 这不是「用了已关闭连接」的 bug。
            return response.status, json.loads(body.decode("utf-8"))
        finally:
            conn.close()

    def test_missing_vault_still_returns_config_with_note(self) -> None:
        status, data = self._get_config()

        # ① 配置本身有效：不是 404、不是 500，也没有 hint 让人「先建库才能看配置」
        self.assertEqual(200, status, data)
        self.assertEqual(str(self.missing.resolve()), data["vault"])
        self.assertEqual(
            str(self.missing.resolve()),
            data["workbuddy"]["config"]["pwdvault"]["env"]["PV_VAULT"],
            "配置里给出的 PV_VAULT 必须就是 settings 里那个（不存在的）真实路径",
        )
        self.assertEqual(
            str(self.missing.resolve()),
            data["deepseek_harness"]["config"]["mcpServers"]["pwdvault"]["env"]["PV_VAULT"],
            "两个客户端的 PV_VAULT 必须一致",
        )

        # ② 必须明确提示「先去 pv init」，否则用户接完只会撞 vault_not_found
        self.assertTrue(
            any("pv init" in note for note in data["notes"]),
            f"库文件不存在时 notes 必须提示先 pv init：{data['notes']}",
        )

        # ③ 反向断言：不能因为「库不存在」就退化成把主密码塞进 env
        for client in ("workbuddy", "deepseek_harness"):
            if client == "workbuddy":
                entry = data["workbuddy"]["config"]["pwdvault"]
            else:
                entry = data["deepseek_harness"]["config"]["mcpServers"]["pwdvault"]
            self.assertNotIn("PV_MASTER_PASSWORD", entry.get("env", {}), client)
        self.assertNotIn("PV_MASTER_PASSWORD", json.dumps(data["workbuddy"], ensure_ascii=False))
        self.assertNotIn(
            "PV_MASTER_PASSWORD", json.dumps(data["deepseek_harness"], ensure_ascii=False)
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
