"""类型化异常体系。

所有对外错误都从这里派生，CLI 层负责把它们翻译成人类可读文案 + 退出码，
绝不把堆栈或内部细节暴露给用户。
"""

from __future__ import annotations


class VaultError(Exception):
    """所有 vault 相关错误的基类。"""

    code = "vault_error"
    exit_code = 1

    def __init__(self, message: str, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def to_dict(self) -> dict:
        payload = {"error": self.code, "message": self.message}
        if self.hint:
            payload["hint"] = self.hint
        return payload


class VaultNotFound(VaultError):
    code = "vault_not_found"
    exit_code = 3

    def __init__(self, path: str) -> None:
        super().__init__(
            f"未找到 vault 文件：{path}",
            hint="先执行 pv init 创建，或用 --vault 指定正确路径。",
        )


class VaultExists(VaultError):
    code = "vault_exists"
    exit_code = 3

    def __init__(self, path: str) -> None:
        super().__init__(
            f"vault 已存在：{path}",
            hint="保护现有数据不会被覆盖。如需重建请先手动移走旧文件。",
        )


class CorruptVault(VaultError):
    code = "vault_corrupt"
    exit_code = 4

    def __init__(self, detail: str) -> None:
        super().__init__(
            f"vault 文件已损坏或格式不识别：{detail}",
            hint="从 snapshots/ 目录里挑一个较新的快照恢复。",
        )


class AuthenticationFailed(VaultError):
    code = "auth_failed"
    exit_code = 5

    def __init__(self, detail: str = "主密码不正确") -> None:
        super().__init__(
            detail,
            hint="密码错误与文件损坏无法区分。若确信密码正确，请检查文件是否被截断。",
        )


class NoUnlockMethod(VaultError):
    code = "no_unlock_method"
    exit_code = 5

    def __init__(self) -> None:
        super().__init__(
            "没有可用的解锁方式",
            hint="该 vault 未启用本机免密；请用 --password-stdin 或交互方式输入主密码。",
        )


class DpapiUnavailable(VaultError):
    code = "dpapi_unavailable"
    exit_code = 6

    def __init__(self, detail: str) -> None:
        super().__init__(f"本机免密不可用：{detail}", hint="改用主密码解锁即可。")


class RecordNotFound(VaultError):
    code = "record_not_found"
    exit_code = 7

    def __init__(self, ref: str) -> None:
        super().__init__(f"找不到记录：{ref}", hint="用 pv find 或 pv list 查看现有条目。")


class AmbiguousRecord(VaultError):
    code = "ambiguous_record"
    exit_code = 7

    def __init__(self, ref: str, candidates: list[str]) -> None:
        super().__init__(
            f"“{ref}”匹配到多条记录：" + "、".join(candidates),
            hint="请改用记录 id 精确指定。",
        )


class InvalidRecord(VaultError):
    code = "invalid_record"
    exit_code = 8

    def __init__(self, detail: str) -> None:
        super().__init__(f"记录数据不合法：{detail}")


class ImportError_(VaultError):
    code = "import_failed"
    exit_code = 8

    def __init__(self, detail: str) -> None:
        super().__init__(f"导入失败：{detail}")


class WeakMasterPassword(VaultError):
    code = "weak_password"
    exit_code = 9

    def __init__(self, detail: str) -> None:
        super().__init__(
            f"主密码强度不足：{detail}",
            hint="文件可能被放在网盘上，攻击者可离线无限次爆破。建议 5 个以上随机单词，"
            "或至少 12 位混合字符。",
        )


class Refused(VaultError):
    code = "refused"
    exit_code = 10

    def __init__(self, detail: str) -> None:
        super().__init__(detail)


# ---------------------------------------------------------------- v1.1 新增
class LockTimeout(VaultError):
    """等写锁超时。文案只说现象，不带任何字段值。"""

    code = "lock_timeout"
    exit_code = 11

    def __init__(self, timeout: float = 3.0, purpose: str = "") -> None:
        prefix = f"{purpose}时" if purpose else ""
        super().__init__(
            f"{prefix}另一个窗口正在写入，等了 {float(timeout):g} 秒还没轮到",
            hint="另一个窗口正在写入，稍等一下再试。",
        )
        self.timeout = float(timeout)
        self.purpose = purpose


class RecordConflict(VaultError):
    """记录级冲突：同一条记录被两边改过，或已被删除。"""

    code = "record_conflict"
    exit_code = 12

    def __init__(
        self,
        record_id: str = "",
        *,
        kind: str = "stale",
        mine: dict | None = None,
        theirs: dict | None = None,
        detail: str = "",
    ) -> None:
        if detail:
            message = detail
        elif kind == "deleted":
            message = "这条记录已被另一个窗口删除。"
        else:
            message = "这条记录刚被另一个窗口改过。"
        super().__init__(message, hint="选择「保留我的」或「采用新的」，不会静默覆盖。")
        self.record_id = record_id
        self.kind = kind
        self.mine = dict(mine or {})
        self.theirs = dict(theirs or {}) if theirs is not None else None

    def to_dict(self) -> dict:
        payload = super().to_dict()
        payload["conflict"] = {
            "record_id": self.record_id,
            "kind": self.kind,
            "mine": dict(self.mine),
            "theirs": dict(self.theirs) if self.theirs is not None else None,
        }
        return payload


class StagingBusy(VaultError):
    """暂存批次状态不允许当前操作（含非法状态转换）。"""

    code = "staging_busy"
    exit_code = 13

    def __init__(self, detail: str) -> None:
        super().__init__(detail, hint="等当前操作结束再试，或先刷新一下待整理页。")


class Locked(VaultError):
    """密码库当前是锁着的。"""

    code = "locked"
    exit_code = 14

    def __init__(
        self,
        message: str = "密码库现在是锁着的。",
        hint: str | None = "先运行 pv local-unlock on 启用本机免密，或用 PV_MASTER_PASSWORD 环境变量提供主密码。",
    ) -> None:
        super().__init__(message, hint=hint)


class StaleWrite(VaultError):
    """要在已变化的文件上写入。用于拒绝静默覆盖。"""

    code = "stale_write"
    exit_code = 15

    def __init__(self, detail: str = "") -> None:
        super().__init__(
            detail or "文件已被另一个窗口改动，这次写入会覆盖别人的修改。",
            hint="刷新后重试；程序不会静默覆盖别人的改动。",
        )


class StagingNotFound(VaultError):
    code = "staging_not_found"
    exit_code = 16

    def __init__(self, batch_id: str) -> None:
        super().__init__(f"找不到待整理批次：{batch_id}", hint="刷新待整理列表看看它是否已被清理。")


class VaultReplaced(VaultError):
    """vault 文件被换成了另一个库，内存里的 DEK 已失效。"""

    code = "vault_replaced"
    exit_code = 17

    def __init__(self, detail: str = "") -> None:
        super().__init__(
            detail or "密码库文件已被替换成另一个库，当前解锁状态不再有效。",
            hint="请重新解锁。",
        )
