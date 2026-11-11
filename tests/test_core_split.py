# -*- coding: utf-8 -*-
"""``core/utils.py`` 拆分（V1.4 任务17）的兼容性与回归测试。

覆盖：

1. shim 身份一致性：``utils.X is core.paths.X`` 等（同一函数对象，而非行为复制）；
2. ``core.paths`` / ``core.acl`` / ``core.whitelist`` / ``core.subprocess_util`` 基本行为；
3. ``hidden_process_options`` 的 Windows 隐藏窗口构造（含 subprocess 常量不可用降级）；
4. ``run_cmd`` / ``run_powershell`` / ``run_powershell_json`` 的构造、超时与失败降级；
5. 拆分模块无循环导入（含全新解释器里的导入顺序验证）；
6. ``utils`` 仍暴露拆分前的全部公共 API 与常量。

所有测试都不需要管理员权限，也不写系统目录（临时文件使用 tempfile）。

运行方式（仓库根目录）::

    python -m pytest -q tests/test_core_split.py
"""

from __future__ import annotations

import importlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import acl, paths, subprocess_util, utils, whitelist  # noqa: E402
from core.finding import make_finding  # noqa: E402

_IS_WINDOWS = os.name == "nt"

# 历史上被外部直接 import / 引用的公共名称（拆分后必须仍在 core.utils 命名空间中）
_LEGACY_PUBLIC_NAMES = (
    # paths
    "BASE_DIR",
    "IS_WINDOWS",
    "RULES_DIR",
    "SYSTEM_BINARY_NAMES",
    "SYSTEM_COMPONENT_NAME_KEYWORDS",
    "TOOLS_DIR",
    "YARA_RULES_DIR",
    "expand_vars",
    "extract_executable",
    "get_base_dir",
    "is_in_system_dir",
    "is_pe_executable",
    "is_system_binary_name",
    "is_trusted_install_location",
    "load_json",
    "looks_like_system_component_name",
    "normalize_path",
    "path_under",
    "resolve_executable",
    "system_roots",
    "truncate",
    # acl
    "is_admin",
    "is_user_writable",
    "user_writable_roots",
    # subprocess_util
    "hidden_process_options",
    "run_cmd",
    "run_powershell",
    "run_powershell_json",
    # whitelist
    "DEFAULT_WHITELIST",
    "apply_whitelist",
    "load_whitelist",
    "match_whitelist",
    # 未拆分、仍定义在 utils 内的内容
    "setup_console",
    "match_suspicious_cmdline",
    "is_suspicious_cmdline",
)


def _fresh_import(code: str) -> subprocess.CompletedProcess[str]:
    """在全新解释器中执行导入语句，用于验证真实导入顺序下没有循环依赖。"""
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )


def _finding(**overrides: object) -> dict[str, object]:
    base = {
        "severity": "HIGH",
        "category": "Test",
        "target": "C:\\Temp\\evil.exe",
        "detail": "test finding",
        "evidence": {"signer": "Contoso Ltd"},
        "rule_id": "TEST_RULE",
    }
    base.update(overrides)
    return make_finding(
        str(base["severity"]),
        str(base["category"]),
        str(base["target"]),
        str(base["detail"]),
        dict(base["evidence"]),  # type: ignore[arg-type]
        str(base["rule_id"]),
    )


class TestShimIdentity(unittest.TestCase):
    """兼容 shim 必须再导出同一对象，而不是复制实现。"""

    def test_paths_functions_identity(self) -> None:
        for name in paths.__all__:
            with self.subTest(name=name):
                self.assertIs(getattr(utils, name), getattr(paths, name))

    def test_acl_functions_identity(self) -> None:
        for name in acl.__all__:
            with self.subTest(name=name):
                self.assertIs(getattr(utils, name), getattr(acl, name))

    def test_subprocess_functions_identity(self) -> None:
        for name in subprocess_util.__all__:
            with self.subTest(name=name):
                self.assertIs(getattr(utils, name), getattr(subprocess_util, name))

    def test_whitelist_functions_identity(self) -> None:
        for name in whitelist.__all__:
            with self.subTest(name=name):
                self.assertIs(getattr(utils, name), getattr(whitelist, name))

    def test_constants_identity(self) -> None:
        self.assertIs(utils.RULES_DIR, paths.RULES_DIR)
        self.assertIs(utils.TOOLS_DIR, paths.TOOLS_DIR)
        self.assertIs(utils.BASE_DIR, paths.BASE_DIR)
        self.assertIs(utils.YARA_RULES_DIR, paths.YARA_RULES_DIR)
        self.assertIs(utils.IS_WINDOWS, paths.IS_WINDOWS)
        self.assertIs(utils.SYSTEM_BINARY_NAMES, paths.SYSTEM_BINARY_NAMES)
        self.assertIs(utils.SYSTEM_COMPONENT_NAME_KEYWORDS, paths.SYSTEM_COMPONENT_NAME_KEYWORDS)
        self.assertIs(utils.DEFAULT_WHITELIST, whitelist.DEFAULT_WHITELIST)

    def test_unsplit_functions_stay_in_utils(self) -> None:
        self.assertEqual(utils.setup_console.__module__, "core.utils")
        self.assertEqual(utils.match_suspicious_cmdline.__module__, "core.utils")
        self.assertEqual(utils.is_suspicious_cmdline.__module__, "core.utils")


class TestPublicApiSurface(unittest.TestCase):
    def test_utils_exposes_legacy_public_names(self) -> None:
        missing = [name for name in _LEGACY_PUBLIC_NAMES if not hasattr(utils, name)]
        self.assertEqual(missing, [])

    def test_new_modules_define_all(self) -> None:
        for module in (paths, acl, subprocess_util, whitelist):
            with self.subTest(module=module.__name__):
                exported = module.__all__
                self.assertIsInstance(exported, list)
                self.assertTrue(exported)
                for name in exported:
                    self.assertTrue(hasattr(module, name), f"{module.__name__} 缺少 {name}")
                    self.assertFalse(name.startswith("_"), f"{module.__name__}.__all__ 不应导出私有名 {name}")

    def test_core_package_still_imports_utils(self) -> None:
        self.assertIs(importlib.import_module("core.utils"), utils)
        self.assertIs(importlib.import_module("core.paths"), paths)
        self.assertIs(importlib.import_module("core.acl"), acl)
        self.assertIs(importlib.import_module("core.subprocess_util"), subprocess_util)
        self.assertIs(importlib.import_module("core.whitelist"), whitelist)

    def test_scanner_still_imports_shim_functions(self) -> None:
        import core.scanner as scanner

        self.assertIs(scanner.apply_whitelist, utils.apply_whitelist)
        self.assertIs(scanner.load_whitelist, utils.load_whitelist)

    def test_module_level_from_import_still_works(self) -> None:
        from modules import lsa_appinit

        self.assertIs(lsa_appinit.truncate, paths.truncate)
        self.assertIs(lsa_appinit.utils, utils)


class TestNoCircularImport(unittest.TestCase):
    """拆分模块不得反向 import core.utils（否则 shim 会形成环）。"""

    def test_split_modules_do_not_import_utils(self) -> None:
        forbidden = ("from . import utils", "from .utils import", "import core.utils", "from core import utils")
        for module in (paths, acl, subprocess_util, whitelist):
            source = inspect.getsource(module)
            for needle in forbidden:
                with self.subTest(module=module.__name__, needle=needle):
                    self.assertNotIn(needle, source)

    def test_shim_imports_split_modules(self) -> None:
        source = inspect.getsource(utils)
        for needle in ("from .paths import *", "from .acl import *", "from .subprocess_util import *", "from .whitelist import *"):
            with self.subTest(needle=needle):
                self.assertIn(needle, source)

    def test_fresh_import_shim_first(self) -> None:
        completed = _fresh_import(
            "import core.utils, core.paths, core.acl, core.subprocess_util, core.whitelist; print('ok')"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ok", completed.stdout)

    def test_fresh_import_split_modules_first(self) -> None:
        completed = _fresh_import(
            "import core.paths, core.acl, core.subprocess_util, core.whitelist, core.utils; print('ok')"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("ok", completed.stdout)

    def test_fresh_import_entrypoints(self) -> None:
        completed = _fresh_import("import main, gui, reporter, core.utils; print('ok')")
        self.assertEqual(completed.returncode, 0, completed.stderr)


@unittest.skipUnless(_IS_WINDOWS, "Windows 路径语义")
class TestPaths(unittest.TestCase):
    def test_normalize_path_table(self) -> None:
        cases = [
            ("", ""),
            ("   ", ""),
            ('"C:\\Windows\\System32\\cmd.exe"', os.path.normpath("C:\\Windows\\System32\\cmd.exe")),
            ("C:/Windows//System32/", os.path.normpath("C:\\Windows\\System32")),
            ("  C:\\Windows\\System32\\cmd.exe  ", os.path.normpath("C:\\Windows\\System32\\cmd.exe")),
            ("\\\\?\\C:\\Windows\\x.exe", os.path.normpath("C:\\Windows\\x.exe")),
        ]
        for raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(paths.normalize_path(raw), expected)

    def test_normalize_path_expands_vars(self) -> None:
        os.environ["TAMPER_SCAN_SPLIT_VAR"] = r"C:\Windows"
        try:
            self.assertEqual(
                paths.normalize_path("%TAMPER_SCAN_SPLIT_VAR%\\System32\\cmd.exe"),
                os.path.normpath(r"C:\Windows\System32\cmd.exe"),
            )
        finally:
            os.environ.pop("TAMPER_SCAN_SPLIT_VAR", None)

    def test_expand_vars(self) -> None:
        os.environ["TAMPER_SCAN_SPLIT_VAR"] = "abc"
        try:
            self.assertEqual(paths.expand_vars("%TAMPER_SCAN_SPLIT_VAR%\\x"), "abc\\x")
        finally:
            os.environ.pop("TAMPER_SCAN_SPLIT_VAR", None)
        self.assertEqual(paths.expand_vars(None), "")
        self.assertEqual(paths.expand_vars(""), "")

    def test_extract_executable_table(self) -> None:
        self.assertEqual(
            paths.extract_executable('"C:\\Program Files\\App\\app.exe" /silent'),
            os.path.normpath("C:\\Program Files\\App\\app.exe"),
        )
        self.assertEqual(
            paths.extract_executable("C:\\Windows\\System32\\cmd.exe /c whoami"),
            os.path.normpath("C:\\Windows\\System32\\cmd.exe"),
        )
        # Userinit 常见的尾逗号形式
        self.assertEqual(
            paths.extract_executable("C:\\Windows\\system32\\userinit.exe,"),
            os.path.normpath("C:\\Windows\\system32\\userinit.exe"),
        )
        self.assertEqual(paths.extract_executable(""), "")
        self.assertEqual(paths.extract_executable(None), "")
        self.assertEqual(paths.extract_executable("not_a_real_command_xyz"), "not_a_real_command_xyz")

    def test_is_in_system_dir(self) -> None:
        system_root = paths.system_roots()[0]
        self.assertTrue(paths.is_in_system_dir(os.path.join(system_root, "evil.exe")))
        self.assertFalse(paths.is_in_system_dir(r"C:\Users\Public\evil.exe"))
        self.assertFalse(paths.is_in_system_dir(""))

    def test_path_under(self) -> None:
        self.assertTrue(paths.path_under(r"C:\WINDOWS\SYSTEM32\X.EXE", r"C:\Windows\System32"))
        self.assertTrue(paths.path_under(r"C:\Windows\System32", r"C:\Windows\System32"))
        self.assertFalse(paths.path_under(r"C:\Windows\System32X\a.exe", r"C:\Windows\System32"))
        self.assertFalse(paths.path_under("", r"C:\Windows"))

    def test_truncate(self) -> None:
        self.assertEqual(paths.truncate("  a   b\tc  "), "a b c")
        self.assertEqual(paths.truncate("x" * 10, limit=5), "xxxx…")
        self.assertEqual(paths.truncate(None), "")

    def test_is_pe_executable(self) -> None:
        for path in ("a.exe", "a.dll", "a.sys", "a.msi", r"C:\Windows\System32\cmd.exe"):
            with self.subTest(path=path):
                self.assertTrue(paths.is_pe_executable(path))
        for path in ("a.ps1", "a.bat", "a.txt", "", None):
            with self.subTest(path=path):
                self.assertFalse(paths.is_pe_executable(path))

    def test_system_helpers(self) -> None:
        self.assertIn("svchost.exe", paths.SYSTEM_BINARY_NAMES)
        self.assertTrue(paths.is_system_binary_name(r"C:\Users\Public\SVCHOST.EXE"))
        self.assertTrue(paths.is_trusted_install_location(r"C:\Windows\System32\cmd.exe"))
        self.assertFalse(paths.is_trusted_install_location(r"C:\Users\Public\evil.exe"))
        self.assertTrue(paths.looks_like_system_component_name("Windows Defender Update"))
        self.assertFalse(paths.looks_like_system_component_name(""))

    def test_directory_constants(self) -> None:
        self.assertEqual(paths.BASE_DIR, paths.get_base_dir())
        self.assertEqual(paths.RULES_DIR, paths.BASE_DIR / "rules")
        self.assertEqual(paths.TOOLS_DIR, paths.BASE_DIR / "tools")
        self.assertEqual(paths.YARA_RULES_DIR, paths.RULES_DIR / "yara")

    def test_load_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "good.json"
            good.write_text('{"a": 1}', encoding="utf-8")
            bad = Path(tmp) / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            self.assertEqual(paths.load_json(good), {"a": 1})
            self.assertIsNone(paths.load_json(bad, default=None))
            self.assertEqual(paths.load_json(Path(tmp) / "missing.json", default={}), {})
            self.assertIsNone(paths.load_json(None))


class TestAcl(unittest.TestCase):
    def test_is_admin_returns_bool(self) -> None:
        self.assertIsInstance(acl.is_admin(), bool)

    def test_user_writable_roots(self) -> None:
        roots = acl.user_writable_roots()
        self.assertIsInstance(roots, list)
        self.assertTrue(roots)
        self.assertTrue(all(isinstance(root, str) and root for root in roots))
        self.assertTrue(any(os.path.normcase(tempfile.gettempdir()) in os.path.normcase(root) for root in roots))

    def test_is_user_writable_temp_nonexistent(self) -> None:
        candidate = os.path.join(tempfile.gettempdir(), "tamper_scan_split_nonexistent_abc.exe")
        self.assertTrue(acl.is_user_writable(candidate))

    @unittest.skipUnless(_IS_WINDOWS, "Windows 系统目录语义")
    def test_is_user_writable_system_dir_false(self) -> None:
        candidate = os.path.join(paths.system_roots()[0], "tamper_scan_split_evil.exe")
        self.assertFalse(acl.is_user_writable(candidate))

    def test_is_user_writable_empty_and_none(self) -> None:
        for value in (None, "", "   "):
            with self.subTest(value=value):
                self.assertFalse(acl.is_user_writable(value))

    def test_is_user_writable_acl_probe_denies(self) -> None:
        candidate = os.path.join(tempfile.gettempdir(), "tamper_scan_split_probe.exe")
        with (
            mock.patch.object(acl, "_path_exists", return_value=True),
            mock.patch.object(acl, "_probe_user_write", return_value=False) as probe,
        ):
            self.assertFalse(acl.is_user_writable(candidate))
        probe.assert_called_once()


class TestSubprocessUtil(unittest.TestCase):
    def test_create_no_window_constant(self) -> None:
        self.assertIsInstance(subprocess_util._CREATE_NO_WINDOW, int)

    @unittest.skipUnless(_IS_WINDOWS, "仅 Windows 有 STARTUPINFO/SW_HIDE")
    def test_hidden_process_options_windows(self) -> None:
        options = subprocess_util.hidden_process_options()
        self.assertIn("creationflags", options)
        self.assertEqual(options["creationflags"], subprocess.CREATE_NO_WINDOW)
        startupinfo = options.get("startupinfo")
        self.assertIsNotNone(startupinfo)
        self.assertEqual(startupinfo.wShowWindow, subprocess.SW_HIDE)  # type: ignore[attr-defined]
        self.assertTrue(startupinfo.dwFlags & subprocess.STARTF_USESHOWWINDOW)  # type: ignore[attr-defined]

    def test_hidden_process_options_without_startupinfo_support(self) -> None:
        """subprocess 缺少 STARTUPINFO/STARTF_USESHOWWINDOW 时只返回 creationflags。"""
        fake_subprocess = types.SimpleNamespace(CREATE_NO_WINDOW=0x08000000)
        with (
            mock.patch.object(subprocess_util, "IS_WINDOWS", True),
            mock.patch.object(subprocess_util, "subprocess", fake_subprocess),
        ):
            options = subprocess_util.hidden_process_options()
        self.assertEqual(options, {"creationflags": subprocess_util._CREATE_NO_WINDOW})

    def test_hidden_process_options_non_windows(self) -> None:
        with mock.patch.object(subprocess_util, "IS_WINDOWS", False):
            self.assertEqual(subprocess_util.hidden_process_options(), {})

    def test_run_cmd_success_constructs_expected_kwargs(self) -> None:
        completed = types.SimpleNamespace(returncode=0, stdout="hello", stderr="")
        with (
            mock.patch.object(subprocess_util, "hidden_process_options", return_value={}) as hidden,
            mock.patch.object(subprocess_util.subprocess, "run", return_value=completed) as run,
        ):
            result = subprocess_util.run_cmd(
                ["cmd.exe", "/c", "echo hi"], timeout=5, cwd="C:\\", env={"A": "B"}
            )
        hidden.assert_called_once()
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0], ["cmd.exe", "/c", "echo hi"])
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["timeout"], 5)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertEqual(kwargs["encoding"], "utf-8")
        self.assertEqual(kwargs["errors"], "ignore")
        self.assertEqual(kwargs["cwd"], "C:\\")
        self.assertEqual(kwargs["env"], {"A": "B"})
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertIsNone(kwargs["input"])
        self.assertTrue(result["ok"])
        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["stdout"], "hello")
        self.assertEqual(result["stderr"], "")
        self.assertIsNone(result["error"])
        self.assertEqual(result["args"], ["cmd.exe", "/c", "echo hi"])

    def test_run_cmd_string_argument_and_input_text(self) -> None:
        completed = types.SimpleNamespace(returncode=0, stdout="", stderr="")
        with (
            mock.patch.object(subprocess_util, "hidden_process_options", return_value={}),
            mock.patch.object(subprocess_util.subprocess, "run", return_value=completed) as run,
        ):
            result = subprocess_util.run_cmd("echo hi", input_text="data")
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["stdin"], subprocess.PIPE)
        self.assertEqual(kwargs["input"], "data")
        self.assertEqual(result["args"], ["echo hi"])

    def test_run_cmd_timeout_degradation(self) -> None:
        with (
            mock.patch.object(subprocess_util, "hidden_process_options", return_value={}),
            mock.patch.object(
                subprocess_util.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="x", timeout=5)
            ),
        ):
            result = subprocess_util.run_cmd(["x"], timeout=5)
        self.assertFalse(result["ok"])
        self.assertIsNone(result["returncode"])
        self.assertIn("执行超时", result["error"])

    def test_run_cmd_file_not_found_degradation(self) -> None:
        with (
            mock.patch.object(subprocess_util, "hidden_process_options", return_value={}),
            mock.patch.object(subprocess_util.subprocess, "run", side_effect=FileNotFoundError("nope")),
        ):
            result = subprocess_util.run_cmd(["missing.exe"])
        self.assertFalse(result["ok"])
        self.assertIn("程序不存在", result["error"])

    def test_run_cmd_generic_exception_degradation(self) -> None:
        with (
            mock.patch.object(subprocess_util, "hidden_process_options", return_value={}),
            mock.patch.object(subprocess_util.subprocess, "run", side_effect=OSError("boom")),
        ):
            result = subprocess_util.run_cmd(["x"])
        self.assertFalse(result["ok"])
        self.assertIn("OSError", result["error"])
        self.assertIn("boom", result["error"])

    def test_run_powershell_builds_args_and_reuses_run_cmd(self) -> None:
        expected = {"ok": True, "returncode": 0, "stdout": "x", "stderr": "", "error": None, "args": []}
        with mock.patch.object(subprocess_util, "run_cmd", return_value=expected) as run_cmd:
            result = subprocess_util.run_powershell("Get-Date", timeout=7)
        self.assertIs(result, expected)
        args = run_cmd.call_args.args[0]
        self.assertEqual(args[0], "powershell.exe")
        self.assertIn("-NoProfile", args)
        self.assertIn("-NonInteractive", args)
        self.assertIn("-ExecutionPolicy", args)
        self.assertIn("Bypass", args)
        self.assertEqual(args[-2], "-Command")
        self.assertIn("[Console]::OutputEncoding", args[-1])
        self.assertIn("Get-Date", args[-1])
        self.assertEqual(run_cmd.call_args.kwargs["timeout"], 7)

    def test_run_powershell_json_ok(self) -> None:
        with mock.patch.object(
            subprocess_util, "run_cmd", return_value={"ok": True, "stdout": json.dumps({"a": 1}), "error": None}
        ):
            data, error = subprocess_util.run_powershell_json("Get-X")
        self.assertEqual(data, {"a": 1})
        self.assertIsNone(error)

    def test_run_powershell_json_command_failure(self) -> None:
        with mock.patch.object(
            subprocess_util, "run_cmd", return_value={"ok": False, "stdout": "", "error": "boom"}
        ):
            data, error = subprocess_util.run_powershell_json("Get-X")
        self.assertIsNone(data)
        self.assertEqual(error, "boom")

    def test_run_powershell_json_empty_output(self) -> None:
        with mock.patch.object(
            subprocess_util, "run_cmd", return_value={"ok": True, "stdout": "   ", "error": None}
        ):
            data, error = subprocess_util.run_powershell_json("Get-X")
        self.assertIsNone(data)
        self.assertEqual(error, "PowerShell 输出为空")

    def test_run_powershell_json_invalid_json(self) -> None:
        with mock.patch.object(
            subprocess_util, "run_cmd", return_value={"ok": True, "stdout": "not json", "error": None}
        ):
            data, error = subprocess_util.run_powershell_json("Get-X")
        self.assertIsNone(data)
        self.assertTrue(str(error).startswith("JSON 解析失败"))


class TestWhitelist(unittest.TestCase):
    def test_default_whitelist_shape(self) -> None:
        self.assertTrue(whitelist.DEFAULT_WHITELIST["enabled"])
        self.assertEqual(whitelist.DEFAULT_WHITELIST["mode"], "downgrade")
        self.assertIsInstance(whitelist.DEFAULT_WHITELIST["extensions"], dict)
        self.assertIsInstance(whitelist.DEFAULT_WHITELIST["persistence_ext_allow"], list)
        for key in ("paths", "signers", "services", "tasks", "commandline_patterns"):
            self.assertIsInstance(whitelist.DEFAULT_WHITELIST[key], list)

    def test_load_whitelist_default_file(self) -> None:
        config = whitelist.load_whitelist()
        self.assertIsInstance(config["enabled"], bool)
        self.assertIn(config["mode"], ("downgrade", "filter", "off"))
        self.assertIn("extensions", config)
        self.assertIn("persistence_ext_allow", config)
        self.assertTrue(str(config["_source"]).endswith("whitelist.json"))

    def test_load_whitelist_custom_file_normalizes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "whitelist.json"
            target.write_text(
                json.dumps(
                    {
                        "enabled": "yes",
                        "mode": "BADMODE",
                        "paths": ["  C:\\Temp\\evil.exe  ", "", 123],
                        "signers": ["Contoso"],
                    }
                ),
                encoding="utf-8",
            )
            config = whitelist.load_whitelist(target)
        self.assertTrue(config["enabled"])
        self.assertEqual(config["mode"], "downgrade")
        self.assertEqual(config["paths"], ["C:\\Temp\\evil.exe", "123"])
        self.assertEqual(config["signers"], ["Contoso"])
        self.assertTrue(config["_loaded"])
        self.assertEqual(config["_source"], str(target))

    def test_load_whitelist_missing_file_returns_skeleton(self) -> None:
        missing = Path(tempfile.gettempdir()) / "tamper_scan_split_missing_whitelist.json"
        config = whitelist.load_whitelist(missing)
        self.assertFalse(config["_loaded"])
        self.assertTrue(config["enabled"])
        self.assertEqual(config["mode"], "downgrade")

    def test_match_whitelist_signers(self) -> None:
        config = whitelist.load_whitelist()  # 骨架 + 默认值
        config["signers"] = ["Contoso"]
        hit = whitelist.match_whitelist(_finding(), config)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["type"], "signers")

    def test_match_whitelist_persistence_ext_allow(self) -> None:
        config = whitelist.load_whitelist()
        config["persistence_ext_allow"] = [
            {"registry_value_path": "HKLM\\Software\\Test\\Value", "signer_contains": "SteelSeries"}
        ]
        finding = make_finding(
            "MEDIUM",
            "PersistenceExt",
            "HKLM\\Software\\Test\\Value",
            "detail",
            {
                "registry_value_path": "hklm\\software\\test\\value",
                "signature": {"status": "valid", "signer": "SteelSeries Audio"},
            },
            "PERSISTENCE_EXT",
        )
        hit = whitelist.match_whitelist(finding, config)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["type"], "persistence_ext_allow")

    def test_apply_whitelist_downgrade_does_not_mutate_input(self) -> None:
        config = whitelist.load_whitelist()
        config["signers"] = ["Contoso"]
        finding = _finding()
        result = whitelist.apply_whitelist([finding], config, mode="downgrade")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "INFO")
        self.assertTrue(result[0]["evidence"]["whitelisted"])
        self.assertEqual(finding["severity"], "HIGH")
        self.assertNotIn("whitelisted", finding["evidence"])

    def test_apply_whitelist_filter(self) -> None:
        config = whitelist.load_whitelist()
        config["signers"] = ["Contoso"]
        self.assertEqual(whitelist.apply_whitelist([_finding()], config, mode="filter"), [])

    def test_apply_whitelist_off_passthrough(self) -> None:
        config = whitelist.load_whitelist()
        config["signers"] = ["Contoso"]
        finding = _finding()
        result = whitelist.apply_whitelist([finding], config, mode="off")
        self.assertEqual(result, [finding])
        self.assertIs(result[0], finding)

    def test_apply_whitelist_no_match_keeps_finding(self) -> None:
        config = whitelist.load_whitelist()
        config["signers"] = []
        finding = _finding()
        result = whitelist.apply_whitelist([finding], config)
        self.assertEqual(result, [finding])
        self.assertIs(result[0], finding)

    def test_utils_whitelist_functions_usable(self) -> None:
        """20 个模块统一通过 utils.apply_whitelist 收尾，shim 必须继续可用。"""
        config = whitelist.load_whitelist()
        config["signers"] = []
        self.assertEqual(utils.apply_whitelist([], config), [])
        self.assertIs(utils.load_whitelist, whitelist.load_whitelist)


class TestLegacyBehavior(unittest.TestCase):
    """拆分前 utils 上的少量独立函数行为保持。"""

    def test_match_suspicious_cmdline(self) -> None:
        hit = utils.match_suspicious_cmdline("powershell.exe -enc SQBFAFgAIABHAGUAdAAtAEQAYQB0AGUAIAA=")
        self.assertIsNotNone(hit)
        assert hit is not None  # for type checkers
        self.assertEqual(hit["pattern_id"], "powershell_encoded")
        self.assertIn("description", hit)
        self.assertTrue(utils.is_suspicious_cmdline("certutil -urlcache -f http://x/y"))
        self.assertIsNone(utils.match_suspicious_cmdline(""))
        self.assertFalse(utils.is_suspicious_cmdline("notepad.exe C:\\a.txt"))

    def test_setup_console_callable(self) -> None:
        self.assertTrue(callable(utils.setup_console))
        self.assertIsInstance(utils.setup_console.__doc__, str)


if __name__ == "__main__":
    unittest.main(verbosity=2)
