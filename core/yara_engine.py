# -*- coding: utf-8 -*-
"""YARA 文件扫描 + skrapa 进程内存扫描封装（阶段 6）。

- **文件扫描**：逐文件编译 ``rules/yara/*.yar``，某个 ``.yar`` 语法错误只记录到
  ``engine.errors`` 并跳过该文件，不影响其它规则；``scan_file(path)`` 返回命中列表。
- **内存扫描**：用 skrapa 扫描进程可执行内存页（PAGE_EXECUTE_READ /
  PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_WRITECOPY，不扫 PAGE_READONLY 数据段），
  只使用 ``memory_*.yar`` 规则（文件特征规则不用于内存，避免误报）。

实现细节与规范示例的差异（已实测 skrapa 1.0）：
1. skrapa 1.0 的 ``scan_pid(pid, patterns=..., attributes=..., page_filter=...)``
   没有 ``yara_rules``/``mem_attributes`` 参数；但它支持把编译好的 ``yara.Rules``
   作为 pattern（内部 ``YaraPattern``），因此我们传 ``patterns=<memory yara rules>``；
2. ``MemoryAttributes.protect`` 是单个 ``IntEnum``（不能用位或），所以"只扫执行页"
   通过 ``page_filter`` 回调实现（attributes.protect 属于三种执行保护之一）；
3. **skrapa 所有扫描都会先启用 SeDebugPrivilege**：标准用户下对任何进程（包括
   自己的进程）都会抛 ``TokenPrivilegeError``。因此 ``scan_process_memory`` 在
   非管理员下直接返回 ``status="no_privilege"``，调用方必须报
   ``SKIPPED / MEMORY_ACCESS_DENIED``，**绝不能当作"没有命中"**。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from . import utils

try:  # yara-python 可选依赖
    import yara  # type: ignore

    YARA_AVAILABLE = True
    YARA_VERSION = getattr(yara, "__version__", "")
except ImportError:  # pragma: no cover - 环境相关
    yara = None  # type: ignore
    YARA_AVAILABLE = False
    YARA_VERSION = ""

try:  # skrapa 可选依赖（进程内存扫描）
    import skrapa  # type: ignore

    SKRAPA_AVAILABLE = True
    try:
        from skrapa.windows.attributes import AccessProtectionType, MemoryAttributes
    except ImportError:  # 非 Windows 平台
        AccessProtectionType = None  # type: ignore
        MemoryAttributes = None  # type: ignore
except ImportError:  # pragma: no cover - 环境相关
    skrapa = None  # type: ignore
    SKRAPA_AVAILABLE = False
    AccessProtectionType = None  # type: ignore
    MemoryAttributes = None  # type: ignore

_EXECUTABLE_PROTECTIONS = set()
if AccessProtectionType is not None:
    for _name in ("PAGE_EXECUTE_READ", "PAGE_EXECUTE_READWRITE", "PAGE_EXECUTE_WRITECOPY"):
        _value = getattr(AccessProtectionType, _name, None)
        if _value is not None:
            _EXECUTABLE_PROTECTIONS.add(_value)


def executable_page_filter(page: Any) -> bool:
    """skrapa page_filter：只放行可执行保护的内存页（不扫只读数据段）。"""
    attributes = getattr(page, "attributes", None)
    if attributes is None:
        return True
    protect = getattr(attributes, "protect", None)
    if not _EXECUTABLE_PROTECTIONS:
        return True
    return protect in _EXECUTABLE_PROTECTIONS


class YaraEngine:
    """按文件编译的 YARA 引擎；单个规则文件失败不影响其它文件。"""

    def __init__(self, rules_dir: str | Path | None = None):
        self.rules_dir = Path(rules_dir) if rules_dir else utils.YARA_RULES_DIR
        self.rule_sets: list[tuple[str, Any]] = []  # [(文件名, yara.Rules)]
        self.errors: list[dict[str, str]] = []
        self.compiled_files: list[str] = []
        self._compile()

    def _compile(self) -> None:
        if not YARA_AVAILABLE:
            return
        if not self.rules_dir.is_dir():
            self.errors.append({"file": str(self.rules_dir), "error": "规则目录不存在"})
            return
        for path in sorted(self.rules_dir.glob("*.yar")):
            try:
                compiled = yara.compile(filepath=str(path))
            except Exception as exc:  # noqa: BLE001 - 单文件编译失败只记录
                self.errors.append({"file": path.name, "error": f"{type(exc).__name__}: {exc}"})
                continue
            self.rule_sets.append((path.name, compiled))
            self.compiled_files.append(path.name)

    def memory_rules(self) -> list[Any]:
        """只返回 memory_*.yar 的编译结果（供 skrapa 内存扫描）。"""
        return [compiled for name, compiled in self.rule_sets if name.startswith("memory_")]

    def file_scan_rules(self) -> list[tuple[str, Any]]:
        """用于文件扫描的规则集合（排除 memory_* 内存专用规则）。"""
        return [(name, compiled) for name, compiled in self.rule_sets if not name.startswith("memory_")]

    def scan_file(self, path: str | Path, timeout: int = 60) -> list[dict[str, Any]]:
        """扫描单个文件，返回 ``[{rule, tags, meta, rule_file, file}]``。"""
        target = str(path or "")
        if not YARA_AVAILABLE or not self.rule_sets or not target:
            return []
        results: list[dict[str, Any]] = []
        seen: set[str] = set()
        for rule_file, compiled in self.rule_sets:
            try:
                matches = compiled.match(target, timeout=timeout)
            except Exception:  # noqa: BLE001 - 单个规则集匹配失败跳过
                continue
            for match in matches or []:
                name = str(getattr(match, "rule", ""))
                if not name or name in seen:
                    continue
                seen.add(name)
                results.append(
                    {
                        "rule": name,
                        "namespace": str(getattr(match, "namespace", "")),
                        "tags": list(getattr(match, "tags", []) or []),
                        "meta": dict(getattr(match, "meta", {}) or {}),
                        "rule_file": rule_file,
                        "file": target,
                    }
                )
        return results


_ENGINES: dict[str, YaraEngine] = {}


def get_engine(rules_dir: str | Path | None = None) -> YaraEngine:
    """获取/创建引擎（按规则目录缓存）。"""
    key = str(Path(rules_dir).resolve()) if rules_dir else "__default__"
    if key not in _ENGINES:
        _ENGINES[key] = YaraEngine(rules_dir)
    return _ENGINES[key]


def scan_file(path: str | Path) -> list[dict[str, Any]]:
    """便捷函数：用默认规则目录扫描单个文件。"""
    return get_engine().scan_file(path)


def engine_status() -> dict[str, Any]:
    """引擎状态（供 evidence / 报告使用）。"""
    engine = get_engine()
    return {
        "yara_available": YARA_AVAILABLE,
        "yara_version": YARA_VERSION,
        "rules_compiled": list(engine.compiled_files),
        "rule_errors": list(engine.errors),
        "skrapa_available": SKRAPA_AVAILABLE,
        "is_admin": utils.is_admin(),
    }


def scan_process_memory(pid: int, rules_dir: str | Path | None = None) -> dict[str, Any]:
    """扫描进程可执行内存，返回状态字典。

    Returns:
        ``{"status": "ok"|"unavailable"|"no_privilege"|"no_rules"|"access_denied"|"error",
           "hits": [...], "error": str|None}``
        - ``no_privilege``：标准用户无法启用 SeDebugPrivilege（skrapa 实测对任何
          PID 都失败），调用方必须报 SKIPPED 而不是"无命中"。
    """
    result: dict[str, Any] = {"status": "unavailable", "hits": [], "error": None}
    if not SKRAPA_AVAILABLE:
        result["error"] = "skrapa 未安装"
        return result
    if not utils.is_admin():
        # skrapa 到 open_process 时才尝试 SeDebugPrivilege，标准用户必然失败；
        # 这里提前判定，避免"尝试了但没报"的误导性结论。
        result["status"] = "no_privilege"
        result["error"] = "skrapa 需要 SeDebugPrivilege（管理员权限）才能读取进程内存"
        return result

    engine = get_engine(rules_dir)
    memory_rules = engine.memory_rules()
    if not memory_rules:
        result["status"] = "no_rules"
        result["error"] = "没有可用的 memory_*.yar 规则"
        return result

    try:
        hits = list(
            skrapa.scan_pid(
                int(pid),
                patterns=memory_rules,
                page_filter=executable_page_filter,
            )
        )
    except Exception as exc:  # noqa: BLE001 - 区分权限与其它错误
        message = f"{type(exc).__name__}: {exc}"
        lowered = message.lower()
        if (
            "privilege" in lowered
            or "access" in lowered
            or "denied" in lowered
            or "openprocess" in lowered
        ):
            result["status"] = "access_denied"
        else:
            result["status"] = "error"
        result["error"] = message
        return result

    unique: dict[str, dict[str, Any]] = {}
    for hit in hits:
        name = str(getattr(hit, "name", "") or "")
        if not name or name in unique:
            continue
        unique[name] = {
            "rule": name.split(":", 1)[0],
            "match": name,
            "address": hex(int(getattr(hit, "address", 0) or 0)),
            "region_start": hex(int(getattr(hit, "region_start", 0) or 0)),
            "region_size": int(getattr(hit, "region_size", 0) or 0),
        }
    result["status"] = "ok"
    result["hits"] = list(unique.values())
    return result
