# -*- coding: utf-8 -*-
"""``modules/autoruns.py`` 信任边界测试（autorunsc64.exe 执行前强制校验）。

验收要点（V1.4 T1553/T1574 防御）：

- 只有 Authenticode ``valid`` + 微软签名者才可信；
- 可选 ``rules/autoruns_trust.json`` 的 SHA256 白名单：命中才可信，不匹配 → ``sha256_mismatch``；
  配置缺失/损坏时安全回退（仅要求微软签名，无哈希白名单）；
- ``scan()`` 在拿到二进制路径后、执行前强制校验；不可信时只返回一条
  ``AUTORUNS_UNTRUSTED_BINARY`` SKIPPED，**绝不调用 subprocess.run**；
- 全部测试 mock：不执行任何真实 exe，不依赖本机是否安装 autorunsc64.exe。

运行方式（仓库根目录）：

    python -m pytest -q tests\\test_autoruns_trust.py
    python -m unittest discover -s tests -p "test_*.py" -v
    python tests\\test_autoruns_trust.py
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from modules import autoruns  # noqa: E402

_BINARY_CONTENT = b"fake-sysinternals-autorunsc64-binary"
_CSV_HEADER = (
    '"Entry Location","Entry","Category","Enabled","Description",'
    '"Image Path","Launch String","Version","Company","Signer"\n'
)


def _signature(status: str = "valid", signer: str | None = "Microsoft Windows") -> dict[str, object]:
    """构造 core.signature.verify() 的典型返回值。"""
    return {"status": status, "signer": signer, "error": None, "via": "embedded"}


def _make_csv(*rows: str) -> bytes:
    """构造最小 autorunsc CSV（列顺序与真实工具一致）。"""
    return (_CSV_HEADER + "".join(row + "\n" for row in rows)).encode("utf-8")


class _TrustTestBase(unittest.TestCase):
    """每个测试隔离配置路径与临时二进制，避免读取仓库真实 rules/autoruns_trust.json。"""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.root = Path(self._tmpdir.name)
        self.config_path = self.root / "autoruns_trust.json"
        patcher = mock.patch.object(autoruns, "TRUST_CONFIG_PATH", self.config_path)
        patcher.start()
        self.addCleanup(patcher.stop)

        self.binary = self.root / "autorunsc64.exe"
        self.binary.write_bytes(_BINARY_CONTENT)
        self.digest = hashlib.sha256(_BINARY_CONTENT).hexdigest()

    # -- helpers ---------------------------------------------------------

    def write_config(self, payload: object) -> None:
        text = payload if isinstance(payload, str) else json.dumps(payload)
        self.config_path.write_text(text, encoding="utf-8")

    def verify(
        self,
        signature_result: dict[str, object] | None = None,
        *,
        path: str | None = None,
        side_effect: BaseException | None = None,
        **kwargs: object,
    ) -> dict[str, object]:
        """调用真实 verify_autoruns_binary，仅 mock 底层验签。"""
        target = str(self.binary) if path is None else path
        if side_effect is not None:
            patch_kwargs: dict[str, object] = {"side_effect": side_effect}
        else:
            patch_kwargs = {"return_value": signature_result or _signature()}
        with mock.patch.object(autoruns.signature, "verify", **patch_kwargs):
            return autoruns.verify_autoruns_binary(target, **kwargs)


# ---------------------------------------------------------------------------
# 1) 可信正例
# ---------------------------------------------------------------------------


class TestTrustedBinary(_TrustTestBase):
    def test_valid_microsoft_signer_is_trusted(self) -> None:
        result = self.verify()
        self.assertTrue(result["trusted"])
        self.assertEqual(result["reason"], "trusted")
        self.assertEqual(result["signer"], "Microsoft Windows")
        self.assertEqual(result["signature"]["status"], "valid")

    def test_microsoft_signer_match_is_case_insensitive(self) -> None:
        result = self.verify(_signature(signer="MICROSOFT CORPORATION"))
        self.assertTrue(result["trusted"])
        self.assertEqual(result["signer"], "MICROSOFT CORPORATION")

    def test_existing_file_sha256_is_streamed_and_reported(self) -> None:
        result = self.verify()
        self.assertEqual(result["sha256"], self.digest)
        self.assertIsNone(result["sha256_match"])  # 未配置白名单
        self.assertEqual(result["trusted_sha256"], [])

    def test_missing_config_falls_back_to_signature_only(self) -> None:
        # 未写配置文件（路径不存在）
        self.assertFalse(self.config_path.exists())
        result = self.verify()
        self.assertTrue(result["trusted"])
        self.assertEqual(result["trusted_sha256"], [])
        self.assertIsNone(result["sha256_match"])


# ---------------------------------------------------------------------------
# 2) 签名不可信
# ---------------------------------------------------------------------------


class TestUntrustedSignature(_TrustTestBase):
    def test_unsigned_binary_is_untrusted(self) -> None:
        result = self.verify(_signature(status="unsigned", signer=None))
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "unsigned")
        self.assertIsNone(result["signer"])
        self.assertEqual(result["signature"]["status"], "unsigned")

    def test_invalid_signature_is_untrusted(self) -> None:
        result = self.verify(_signature(status="invalid", signer=None))
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "invalid_signature")

    def test_missing_signature_status_is_untrusted(self) -> None:
        result = self.verify(_signature(status="missing", signer=None))
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "missing_file")

    def test_valid_sysinternals_signer_is_untrusted(self) -> None:
        result = self.verify(_signature(signer="Sysinternals"))
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "non_microsoft_signer")

    def test_valid_contoso_signer_is_untrusted(self) -> None:
        result = self.verify(_signature(signer="Contoso Ltd."))
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "non_microsoft_signer")

    def test_valid_but_no_signer_is_untrusted(self) -> None:
        result = self.verify(_signature(signer=None))
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "missing_signer")

    def test_verify_exception_degrades_to_untrusted(self) -> None:
        result = self.verify(side_effect=RuntimeError("wintrust boom"))
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "invalid_signature")
        self.assertIn("wintrust boom", str(result["signature"].get("error")))


# ---------------------------------------------------------------------------
# 3) 空路径 / 不存在
# ---------------------------------------------------------------------------


class TestPathGuards(_TrustTestBase):
    def test_empty_path_is_untrusted_without_exception(self) -> None:
        with mock.patch.object(autoruns.signature, "verify") as mocked_verify:
            for value in ("", "   ", None):
                result = autoruns.verify_autoruns_binary(value)
                self.assertFalse(result["trusted"], value)
                self.assertEqual(result["reason"], "empty_path", value)
        mocked_verify.assert_not_called()

    def test_nonexistent_file_is_missing_file(self) -> None:
        result = autoruns.verify_autoruns_binary(str(self.root / "nope.exe"))
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "missing_file")
        self.assertIsNone(result["sha256"])

    def test_directory_path_is_missing_file(self) -> None:
        result = autoruns.verify_autoruns_binary(str(self.root))
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "missing_file")


# ---------------------------------------------------------------------------
# 4) SHA256 白名单
# ---------------------------------------------------------------------------


class TestSha256Whitelist(_TrustTestBase):
    def test_whitelist_match_is_trusted(self) -> None:
        self.write_config({"trusted_sha256": [self.digest], "require_microsoft_signer": True})
        result = self.verify()
        self.assertTrue(result["trusted"])
        self.assertTrue(result["sha256_match"])
        self.assertEqual(result["sha256"], self.digest)
        self.assertEqual(result["trusted_sha256"], [self.digest])

    def test_whitelist_mismatch_is_untrusted(self) -> None:
        self.write_config({"trusted_sha256": ["0" * 64], "require_microsoft_signer": True})
        result = self.verify()
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "sha256_mismatch")
        self.assertFalse(result["sha256_match"])
        self.assertEqual(result["sha256"], self.digest)
        self.assertEqual(result["expected_sha256"], ["0" * 64])

    def test_empty_whitelist_does_not_reject_by_hash(self) -> None:
        self.write_config({"trusted_sha256": [], "require_microsoft_signer": True})
        result = self.verify()
        self.assertTrue(result["trusted"])
        self.assertIsNone(result["sha256_match"])

    def test_expected_sha256_argument_match(self) -> None:
        result = self.verify(expected_sha256=self.digest)
        self.assertTrue(result["trusted"])
        self.assertTrue(result["sha256_match"])
        self.assertEqual(result["expected_sha256"], [self.digest])

    def test_expected_sha256_argument_mismatch(self) -> None:
        result = self.verify(expected_sha256="a" * 64)
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "sha256_mismatch")

    def test_expected_sha256_argument_accepts_list_and_normalizes_case(self) -> None:
        result = self.verify(expected_sha256=["not-a-hash", " " + self.digest.upper() + " "])
        self.assertTrue(result["trusted"])
        self.assertEqual(result["expected_sha256"], [self.digest])

    def test_expected_sha256_merges_with_config_whitelist(self) -> None:
        self.write_config({"trusted_sha256": ["b" * 64], "require_microsoft_signer": True})
        result = self.verify(expected_sha256=self.digest)
        self.assertTrue(result["trusted"])
        self.assertEqual(result["trusted_sha256"], ["b" * 64])
        self.assertEqual(result["expected_sha256"], ["b" * 64, self.digest])

    def test_unreadable_sha256_with_whitelist_is_rejected(self) -> None:
        self.write_config({"trusted_sha256": [self.digest], "require_microsoft_signer": True})
        with mock.patch.object(autoruns, "_sha256_file", return_value=None):
            result = self.verify()
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "sha256_mismatch")
        self.assertFalse(result["sha256_match"])


# ---------------------------------------------------------------------------
# 5) 配置缺失 / 损坏 / 放宽策略
# ---------------------------------------------------------------------------


class TestTrustConfigFallback(_TrustTestBase):
    def test_corrupt_json_does_not_crash(self) -> None:
        self.write_config("{ this is not valid json ")
        result = self.verify()
        self.assertTrue(result["trusted"])  # 回退为"仅要求微软签名"
        self.assertEqual(result["trusted_sha256"], [])

    def test_non_dict_config_does_not_crash(self) -> None:
        self.write_config([1, 2, 3])
        result = self.verify()
        self.assertTrue(result["trusted"])

    def test_invalid_hash_entries_are_ignored(self) -> None:
        self.write_config({"trusted_sha256": ["not-a-hash", 12345, None, self.digest]})
        result = self.verify()
        self.assertTrue(result["trusted"])
        self.assertEqual(result["trusted_sha256"], [self.digest])

    def test_require_microsoft_false_without_hash_still_rejects_non_microsoft(self) -> None:
        self.write_config({"trusted_sha256": [], "require_microsoft_signer": False})
        result = self.verify(_signature(signer="Sysinternals"))
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "non_microsoft_signer")

    def test_require_microsoft_false_with_hash_pin_accepts_non_microsoft(self) -> None:
        self.write_config({"trusted_sha256": [self.digest], "require_microsoft_signer": False})
        result = self.verify(_signature(signer="Sysinternals"))
        self.assertTrue(result["trusted"])

    def test_require_microsoft_false_with_wrong_hash_rejects_non_microsoft(self) -> None:
        self.write_config({"trusted_sha256": ["c" * 64], "require_microsoft_signer": False})
        result = self.verify(_signature(signer="Sysinternals"))
        self.assertFalse(result["trusted"])
        self.assertEqual(result["reason"], "sha256_mismatch")


# ---------------------------------------------------------------------------
# 6) scan() 集成：不可信绝不执行，可信保持原采集行为
# ---------------------------------------------------------------------------


class TestScanIntegration(_TrustTestBase):
    def _run_scan(
        self,
        *,
        find_result: str | None = None,
        verify_patch: object | None = None,
        run_result: tuple[bytes | None, str | None] = (b"", None),
    ):
        with contextlib.ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(autoruns, "_find_autorunsc", return_value=find_result)
            )
            runner = stack.enter_context(
                mock.patch.object(autoruns, "_run_autorunsc", return_value=run_result)
            )
            subprocess_run = stack.enter_context(mock.patch.object(autoruns.subprocess, "run"))
            if verify_patch is not None:
                stack.enter_context(mock.patch.object(autoruns, "verify_autoruns_binary", verify_patch))
            findings = autoruns.scan()
        return findings, runner, subprocess_run

    def test_untrusted_binary_is_skipped_and_subprocess_not_called(self) -> None:
        untrusted = {
            "trusted": False,
            "reason": "non_microsoft_signer",
            "signature": {"status": "valid", "signer": "Sysinternals", "error": None},
            "signer": "Sysinternals",
            "sha256": self.digest,
            "sha256_match": None,
            "trusted_sha256": [],
        }
        findings, runner, subprocess_run = self._run_scan(
            find_result=str(self.binary),
            verify_patch=mock.Mock(return_value=untrusted),
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "AUTORUNS_UNTRUSTED_BINARY")
        self.assertEqual(findings[0]["category"], "Autoruns")
        self.assertEqual(findings[0]["target"], "autorunsc64.exe")
        self.assertIn("non_microsoft_signer", findings[0]["detail"])
        runner.assert_not_called()
        subprocess_run.assert_not_called()

    def test_scan_blocks_when_native_verify_finds_non_microsoft_signer(self) -> None:
        with (
            mock.patch.object(autoruns, "_find_autorunsc", return_value=str(self.binary)),
            mock.patch.object(autoruns.signature, "verify", return_value=_signature(signer="Contoso Ltd.")),
            mock.patch.object(autoruns, "_run_autorunsc") as runner,
            mock.patch.object(autoruns.subprocess, "run") as subprocess_run,
        ):
            findings = autoruns.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule_id"], "AUTORUNS_UNTRUSTED_BINARY")
        self.assertEqual(findings[0]["evidence"]["signer"], "Contoso Ltd.")
        runner.assert_not_called()
        subprocess_run.assert_not_called()

    def test_untrusted_evidence_fields_are_recorded(self) -> None:
        untrusted = {
            "trusted": False,
            "reason": "sha256_mismatch",
            "signature": {"status": "valid", "signer": "Microsoft Windows", "error": None},
            "signer": "Microsoft Windows",
            "sha256": self.digest,
            "sha256_match": False,
            "trusted_sha256": ["0" * 64],
        }
        findings, _runner, _subprocess_run = self._run_scan(
            find_result=str(self.binary),
            verify_patch=mock.Mock(return_value=untrusted),
        )
        evidence = findings[0]["evidence"]
        self.assertEqual(evidence["binary_path"], str(self.binary))
        self.assertEqual(evidence["reason"], "sha256_mismatch")
        self.assertEqual(evidence["signature_status"], "valid")
        self.assertEqual(evidence["signer"], "Microsoft Windows")
        self.assertEqual(evidence["sha256"], self.digest)
        self.assertFalse(evidence["sha256_match"])
        self.assertEqual(evidence["trusted_sha256"], ["0" * 64])
        self.assertEqual(evidence["expected_sha256"], [autoruns.truncate("0" * 64, 16)])
        self.assertEqual(evidence["actual_sha256"], autoruns.truncate(self.digest, 16))
        self.assertEqual(evidence["signature"]["status"], "valid")

    def test_trusted_binary_continues_collection(self) -> None:
        trusted = {
            "trusted": True,
            "reason": "trusted",
            "signature": {"status": "valid", "signer": "Microsoft Windows"},
            "signer": "Microsoft Windows",
            "sha256": self.digest,
            "sha256_match": None,
            "trusted_sha256": [],
        }
        findings, runner, subprocess_run = self._run_scan(
            find_result=str(self.binary),
            verify_patch=mock.Mock(return_value=trusted),
            run_result=(_make_csv(), None),
        )
        self.assertEqual(findings, [])
        runner.assert_called_once_with(str(self.binary), verify_signatures=True)
        subprocess_run.assert_not_called()

    def test_trusted_binary_parses_rows_as_before(self) -> None:
        row = (
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup,"
            r"Updater.lnk,Startup,enabled,Updater,C:\Windows\System32\svchost.exe,,1.0,"
            r"Microsoft Corporation,Microsoft Windows"
        )
        trusted = {"trusted": True, "reason": "trusted", "signature": {}, "signer": "Microsoft Windows"}
        with (
            mock.patch.object(autoruns, "_find_autorunsc", return_value=str(self.binary)),
            mock.patch.object(autoruns, "verify_autoruns_binary", return_value=trusted),
            mock.patch.object(
                autoruns, "_run_autorunsc", return_value=(_make_csv(row), None)
            ) as runner,
            mock.patch.object(autoruns.signature, "signature_finding", return_value=None),
            mock.patch.object(autoruns.utils, "is_user_writable", return_value=False),
            mock.patch.object(autoruns.utils, "match_suspicious_cmdline", return_value=None),
        ):
            findings = autoruns.scan()
        self.assertEqual(findings, [])
        runner.assert_called_once_with(str(self.binary), verify_signatures=True)

    def test_missing_binary_still_uses_v13_skipped_path(self) -> None:
        with (
            mock.patch.object(autoruns, "_find_autorunsc", return_value=None),
            mock.patch.object(autoruns, "verify_autoruns_binary") as verifier,
            mock.patch.object(autoruns, "_run_autorunsc") as runner,
        ):
            findings = autoruns.scan()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "SKIPPED")
        self.assertEqual(findings[0]["rule_id"], "AUTORUNS_SKIPPED")
        verifier.assert_not_called()
        runner.assert_not_called()

    def test_trust_check_runs_before_execution(self) -> None:
        calls: list[str] = []
        trusted = {"trusted": True, "reason": "trusted", "signature": {}, "signer": "Microsoft Windows"}

        def _verify(_path: str) -> dict[str, object]:
            calls.append("verify")
            return trusted

        def _run(*_args: object, **_kwargs: object) -> tuple[bytes | None, str | None]:
            calls.append("run")
            return (_make_csv(), None)

        with (
            mock.patch.object(autoruns, "_find_autorunsc", return_value=str(self.binary)),
            mock.patch.object(autoruns, "verify_autoruns_binary", side_effect=_verify),
            mock.patch.object(autoruns, "_run_autorunsc", side_effect=_run),
        ):
            autoruns.scan()
        self.assertEqual(calls, ["verify", "run"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
