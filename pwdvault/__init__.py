"""pwdvault —— 零知识本地密码库。

密文文件可以放心放在任何网盘上，密钥永远不离开本机。

分层（只允许箭头向下）：
    crypto dpapi models errors config   加密原语 / 平台绑定 / 模型 / 异常 / 配置
    vault                              文件格式、原子写入、快照
    locks importers clipboard redact   跨进程锁与 rebase / 解析 / 剪贴板 / 脱敏出口
    service staging inbox              业务规则 / 暂存区 / inbox 监听
    web mcp_server mcp_tools           传输层
    cli                                控制器：参数解析与输出
"""

from .config import FORMAT_VERSION, load_settings
from .errors import VaultError
from .models import Record
from .vault import Vault

__all__ = ["Vault", "Record", "VaultError", "load_settings", "FORMAT_VERSION"]
__version__ = "1.1.0"
