# -*- coding: utf-8 -*-
"""Authenticode 静态信任层（阶段 1）。

- 验签：``ctypes`` 调用 ``wintrust.dll!WinVerifyTrust``，
  策略 GUID 为 ``WINTRUST_ACTION_GENERIC_VERIFY_V2``，返回 0 表示签名有效；
  先校验 **嵌入签名**（WTD_CHOICE_FILE）；若文件没有嵌入签名，再通过
  ``CryptCATAdmin*`` 找到其所属目录签名（catalog）并用 WTD_CHOICE_CATALOG 复验
  （Windows 10/11 大量系统文件只有目录签名，例如 notepad.exe）；
- 签名者：验签成功后从 ``hWVTStateData`` 经 ``WTHelper*`` 拿到证书链，
  用 ``CertGetNameStringW`` 取签名者显示名（如 ``Microsoft Windows``）；
- ``pefile`` **只用于提取 PE 元数据**（OriginalFilename / CompanyName /
  FileDescription / FileVersion），**绝不参与验签**；
- 结果做进程内缓存（``verify`` / ``pe_metadata`` 各自一个缓存）。

判定规则（对应 Finding）::

    SIG_UNSIGNED          HIGH    无数字签名（嵌入签名与目录签名均无）
    SIG_INVALID           HIGH    签名无效 / 证书链失败 / 内容被篡改
    SIG_PATH_MASQUERADE   HIGH    非微软签名却位于 System32 / SysWOW64
    SIG_COMPANY_MISMATCH  MEDIUM  签名者与声称的公司不符

注意：``SIG_PATH_MASQUERADE`` 会排除 ``System32\\DriverStore``、
``System32\\drivers``、``System32\\spool\\drivers`` 等"第三方驱动正常存放目录"
（见 :func:`is_masquerade_excluded`）。这些目录里的非微软签名是正常现象，
不排除的话实测会把 NVIDIA/Realtek 等驱动误报成 HIGH 伪装。
"""

from __future__ import annotations

import ctypes
import os
import re
from typing import Any

from . import utils
from .finding import make_finding

IS_WINDOWS = os.name == "nt"

# ---------------------------------------------------------------------------
# 常用 HRESULT 与判定集合
# ---------------------------------------------------------------------------

TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
TRUST_E_BAD_DIGEST = 0x80096010

# 视为"无签名"（不是篡改，只是没带签名）
_UNSIGNED_CODES = {
    TRUST_E_NOSIGNATURE,
    TRUST_E_SUBJECT_FORM_UNKNOWN,
    TRUST_E_PROVIDER_UNKNOWN,
}

# 吊销状态无法离线确认：不判为篡改，仅记录提示
_REVOCATION_OFFLINE_CODES = {
    0x80092013,  # CRYPT_E_REVOCATION_OFFLINE
    0x800B010E,  # CERT_E_REVOCATION_FAILURE
    0x80092012,  # CRYPT_E_NO_REVOCATION_CHECK
}

_HRESULT_MESSAGES: dict[int, str] = {
    0x800B0100: "TRUST_E_NOSIGNATURE：文件没有数字签名",
    0x800B0003: "TRUST_E_SUBJECT_FORM_UNKNOWN：签名主题格式未知",
    0x800B0001: "TRUST_E_PROVIDER_UNKNOWN：未知的信任提供程序",
    0x800B0109: "CERT_E_UNTRUSTEDROOT：证书链根证书不受信任",
    0x800B010A: "CERT_E_CHAINING：证书链构建失败",
    0x800B010C: "CERT_E_REVOKED：证书已被吊销",
    0x800B0101: "CERT_E_EXPIRED：签名证书已过期",
    0x800B0110: "CERT_E_WRONG_USAGE：证书用途与签名不匹配",
    0x800B0111: "TRUST_E_EXPLICIT_DISTRUST：证书被显式不信任",
    0x80096004: "TRUST_E_CERT_SIGNATURE：证书签名校验失败",
    0x80096010: "TRUST_E_BAD_DIGEST：文件内容与签名摘要不符（可能被篡改）",
    0x80092010: "CRYPT_E_REVOKED：证书已被吊销",
    0x80092013: "CRYPT_E_REVOCATION_OFFLINE：吊销服务器不可达",
    0x800B010E: "CERT_E_REVOCATION_FAILURE：吊销检查失败",
    0x80092012: "CRYPT_E_NO_REVOCATION_CHECK：无法执行吊销检查",
}


def _code_message(code: int, fallback: str) -> str:
    message = _HRESULT_MESSAGES.get(code)
    if message:
        return message
    return f"{fallback}（HRESULT 0x{code:08X}）"


# ---------------------------------------------------------------------------
# Win32 结构体与常量
# ---------------------------------------------------------------------------


class _GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pcwszFilePath", ctypes.c_wchar_p),
        ("hFile", ctypes.c_void_p),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.c_ulong),
        ("fdwRevocationChecks", ctypes.c_ulong),
        ("dwUnionChoice", ctypes.c_ulong),
        # union: WTD_CHOICE_FILE 时为 WINTRUST_FILE_INFO*，WTD_CHOICE_CATALOG 时为 WINTRUST_CATALOG_INFO*
        ("pUnion", ctypes.c_void_p),
        ("dwStateAction", ctypes.c_ulong),
        ("hWVTStateData", ctypes.c_void_p),
        ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", ctypes.c_ulong),
        ("dwUIContext", ctypes.c_ulong),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class _WINTRUST_CATALOG_INFO(ctypes.Structure):
    """WINTRUST_CATALOG_INFO（Windows 8+ 布局）。"""

    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("dwCatalogVersion", ctypes.c_ulong),
        ("pcwszCatalogFilePath", ctypes.c_wchar_p),
        ("pcwszMemberTag", ctypes.c_wchar_p),
        ("pcwszMemberFilePath", ctypes.c_wchar_p),
        ("hMemberFile", ctypes.c_void_p),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", ctypes.c_ulong),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", ctypes.c_void_p),
    ]


class _CATALOG_INFO(ctypes.Structure):
    """CATALOG_INFO：CryptCATCatalogInfoFromContext 的输出。"""

    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("wszCatalogFile", ctypes.c_wchar * 260),  # MAX_PATH
    ]


class _CRYPT_PROVIDER_CERT(ctypes.Structure):
    """CRYPT_PROVIDER_CERT 的前半部分（只读 pCert 字段）。"""

    _fields_ = [
        ("cbStruct", ctypes.c_ulong),
        ("pCert", ctypes.c_void_p),
        ("fCommercial", ctypes.c_int),
        ("fTrustedRoot", ctypes.c_int),
        ("fSelfSigned", ctypes.c_int),
        ("fTestCert", ctypes.c_int),
        ("dwRevokedReason", ctypes.c_ulong),
        ("dwConfidence", ctypes.c_ulong),
        ("dwError", ctypes.c_ulong),
        ("sftVerifyAsOf", ctypes.c_ulong * 2),  # FILETIME
        ("dwRegPolicySettings", ctypes.c_ulong),
    ]


_WTD_UI_NONE = 2
_WTD_REVOKE_NONE = 0
_WTD_CHOICE_FILE = 1
_WTD_CHOICE_CATALOG = 2
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000  # 只查本地缓存，杜绝强制联网

_CERT_NAME_SIMPLE_DISPLAY_TYPE = 4


def _make_generic_verify_guid() -> _GUID:
    """WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}"""
    guid = _GUID()
    guid.Data1 = 0x00AAC56B
    guid.Data2 = 0xCD44
    guid.Data3 = 0x11D0
    guid.Data4 = (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
    return guid


_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _make_generic_verify_guid()

# 懒加载的 wintrust.dll / crypt32.dll 函数表
_LIBS: dict[str, Any] | None = None


def _load_libs() -> dict[str, Any]:
    """加载并声明 wintrust.dll / crypt32.dll 的函数签名（进程内只做一次）。"""
    global _LIBS
    if _LIBS is not None:
        return _LIBS
    if not IS_WINDOWS:
        raise OSError("当前平台不支持 WinVerifyTrust")
    wintrust = ctypes.WinDLL("wintrust.dll")  # type: ignore[attr-defined]
    wintrust.WinVerifyTrust.argtypes = [ctypes.c_void_p, ctypes.POINTER(_GUID), ctypes.c_void_p]
    wintrust.WinVerifyTrust.restype = ctypes.c_long
    wintrust.WTHelperProvDataFromStateData.argtypes = [ctypes.c_void_p]
    wintrust.WTHelperProvDataFromStateData.restype = ctypes.c_void_p
    wintrust.WTHelperGetProvSignerFromChain.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    wintrust.WTHelperGetProvSignerFromChain.restype = ctypes.c_void_p
    wintrust.WTHelperGetProvCertFromChain.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    wintrust.WTHelperGetProvCertFromChain.restype = ctypes.c_void_p

    crypt32 = ctypes.WinDLL("crypt32.dll")  # type: ignore[attr-defined]
    crypt32.CertGetNameStringW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_ulong,
    ]
    crypt32.CertGetNameStringW.restype = ctypes.c_ulong

    # 目录签名（catalog）相关：用于复验没有嵌入签名的文件
    wintrust.CryptCATAdminAcquireContext.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(_GUID),
        ctypes.c_ulong,
    ]
    wintrust.CryptCATAdminAcquireContext.restype = ctypes.c_int
    wintrust.CryptCATAdminCalcHashFromFileHandle.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_ulong,
    ]
    wintrust.CryptCATAdminCalcHashFromFileHandle.restype = ctypes.c_int
    wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ubyte),
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    wintrust.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
    wintrust.CryptCATCatalogInfoFromContext.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_CATALOG_INFO),
        ctypes.c_ulong,
    ]
    wintrust.CryptCATCatalogInfoFromContext.restype = ctypes.c_int
    wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    wintrust.CryptCATAdminReleaseCatalogContext.restype = ctypes.c_int
    wintrust.CryptCATAdminReleaseContext.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    wintrust.CryptCATAdminReleaseContext.restype = ctypes.c_int

    _LIBS = {"wintrust": wintrust, "crypt32": crypt32}
    return _LIBS


def _close_wintrust_state(libs: dict[str, Any], trust_data: _WINTRUST_DATA) -> None:
    """关闭 WinVerifyTrust 状态句柄（必须成对调用，避免句柄泄漏）。"""
    try:
        if trust_data.hWVTStateData:
            trust_data.dwStateAction = _WTD_STATEACTION_CLOSE
            libs["wintrust"].WinVerifyTrust(
                None,
                ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(trust_data),
            )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 签名者提取
# ---------------------------------------------------------------------------


def _extract_signer(state_handle: int | None) -> str | None:
    """从 WinVerifyTrust 的状态数据中取签名者显示名；失败返回 None。"""
    if not state_handle:
        return None
    try:
        libs = _load_libs()
        wintrust = libs["wintrust"]
        crypt32 = libs["crypt32"]
        provider = wintrust.WTHelperProvDataFromStateData(ctypes.c_void_p(state_handle))
        if not provider:
            return None
        signer = wintrust.WTHelperGetProvSignerFromChain(ctypes.c_void_p(provider), 0, 0, 0)
        if not signer:
            return None
        provider_cert = wintrust.WTHelperGetProvCertFromChain(ctypes.c_void_p(signer), 0)
        if not provider_cert:
            return None
        cert_struct = ctypes.cast(ctypes.c_void_p(provider_cert), ctypes.POINTER(_CRYPT_PROVIDER_CERT)).contents
        cert_context = ctypes.c_void_p(cert_struct.pCert)
        if not cert_context:
            return None
        # 第一次取长度（包含结尾 \0），第二次取值
        size = int(crypt32.CertGetNameStringW(cert_context, _CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, None, 0))
        if size <= 1:
            return None
        buffer = ctypes.create_unicode_buffer(size)
        written = int(
            crypt32.CertGetNameStringW(cert_context, _CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buffer, size)
        )
        if written <= 1:
            return None
        return buffer.value.strip() or None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 缓存与路径工具
# ---------------------------------------------------------------------------

_VERIFY_CACHE: dict[str, dict[str, Any]] = {}
_PE_CACHE: dict[str, dict[str, Any]] = {}


def clear_cache() -> None:
    """清空验签与 PE 元数据缓存（测试/长驻进程复用）。"""
    _VERIFY_CACHE.clear()
    _PE_CACHE.clear()


def _abs_path(path: Any) -> str:
    text = str(path or "").strip().strip('"').strip("'").strip()
    if not text:
        return ""
    text = utils.expand_vars(text)
    if not os.path.isfile(text):
        # 兼容 "C:\x\a.exe -arg" 这类启动字符串
        alternative = utils.extract_executable(text)
        if alternative and os.path.isfile(alternative):
            text = alternative
    try:
        return os.path.abspath(text)
    except Exception:
        return text


def _catalog_verify(absolute: str) -> dict[str, Any] | None:
    """用目录签名（catalog）复验文件（无嵌入签名的系统文件走这条路）。

    Returns:
        ``{"status","signer","error","via"}``；文件不在任何目录签名中时返回 None。
    """
    try:
        libs = _load_libs()
    except Exception:
        return None
    wintrust = libs["wintrust"]
    try:
        import msvcrt  # 取 Python 文件对象的 Win32 HANDLE
    except ImportError:
        return None

    h_cat_admin = ctypes.c_void_p()
    if not wintrust.CryptCATAdminAcquireContext(ctypes.byref(h_cat_admin), None, 0):
        return None
    h_cat_info: Any = None
    trust_data: _WINTRUST_DATA | None = None
    try:
        with open(absolute, "rb") as file_handle:
            os_handle = ctypes.c_void_p(msvcrt.get_osfhandle(file_handle.fileno()))
            hash_size = ctypes.c_ulong(0)
            if not wintrust.CryptCATAdminCalcHashFromFileHandle(os_handle, ctypes.byref(hash_size), None, 0):
                return None
            if not hash_size.value:
                return None
            hash_buffer = (ctypes.c_ubyte * hash_size.value)()
            if not wintrust.CryptCATAdminCalcHashFromFileHandle(
                os_handle, ctypes.byref(hash_size), hash_buffer, 0
            ):
                return None
            h_cat_info = wintrust.CryptCATAdminEnumCatalogFromHash(
                h_cat_admin, hash_buffer, hash_size.value, 0, None
            )
        if not h_cat_info:
            return None

        catalog_info = _CATALOG_INFO()
        catalog_info.cbStruct = ctypes.sizeof(_CATALOG_INFO)
        if not wintrust.CryptCATCatalogInfoFromContext(
            ctypes.c_void_p(h_cat_info), ctypes.byref(catalog_info), 0
        ):
            return None
        catalog_path = str(catalog_info.wszCatalogFile or "")
        if not catalog_path:
            return None

        catalog_member = _WINTRUST_CATALOG_INFO()
        catalog_member.cbStruct = ctypes.sizeof(_WINTRUST_CATALOG_INFO)
        catalog_member.dwCatalogVersion = 0
        catalog_member.pcwszCatalogFilePath = catalog_path
        catalog_member.pcwszMemberTag = None
        catalog_member.pcwszMemberFilePath = absolute
        catalog_member.hMemberFile = None
        catalog_member.pbCalculatedFileHash = hash_buffer
        catalog_member.cbCalculatedFileHash = hash_size.value
        catalog_member.pcCatalogContext = None
        catalog_member.hCatAdmin = h_cat_admin

        trust_data = _WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        trust_data.dwUIChoice = _WTD_UI_NONE
        trust_data.fdwRevocationChecks = _WTD_REVOKE_NONE
        trust_data.dwUnionChoice = _WTD_CHOICE_CATALOG
        trust_data.pUnion = ctypes.cast(ctypes.pointer(catalog_member), ctypes.c_void_p)
        trust_data.dwStateAction = _WTD_STATEACTION_VERIFY
        trust_data.dwProvFlags = _WTD_CACHE_ONLY_URL_RETRIEVAL
        trust_data.dwUIContext = 0

        result: dict[str, Any] = {"status": "unsigned", "signer": None, "error": None, "via": "catalog"}
        hresult = int(
            wintrust.WinVerifyTrust(
                None,
                ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(trust_data),
            )
        )
        code = hresult & 0xFFFFFFFF
        if code == 0:
            result["status"] = "valid"
            result["signer"] = _extract_signer(trust_data.hWVTStateData)
        elif code in _UNSIGNED_CODES:
            result["status"] = "unsigned"
            result["error"] = _code_message(code, "目录签名没有有效签名")
        else:
            result["status"] = "invalid"
            result["error"] = _code_message(code, "目录签名校验失败")
        return result
    except Exception:
        return None
    finally:
        if trust_data is not None:
            _close_wintrust_state(libs, trust_data)
        if h_cat_info:
            try:
                wintrust.CryptCATAdminReleaseCatalogContext(h_cat_admin, h_cat_info, 0)
            except Exception:
                pass
        try:
            wintrust.CryptCATAdminReleaseContext(h_cat_admin, 0)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# 核心 API
# ---------------------------------------------------------------------------


def verify(path: Any) -> dict[str, Any]:
    """校验单个文件的 Authenticode 签名（嵌入签名优先，其次目录签名）。

    Returns:
        ``{"status": "valid" | "invalid" | "unsigned" | "missing",
           "signer": str | None, "error": str | None, "via": "embedded" | "catalog" | None}``
    """
    result: dict[str, Any] = {"status": "missing", "signer": None, "error": None, "via": None}
    absolute = _abs_path(path)
    if not absolute:
        result["error"] = "路径为空"
        return result
    cache_key = os.path.normcase(absolute)
    if cache_key in _VERIFY_CACHE:
        return dict(_VERIFY_CACHE[cache_key])
    if not os.path.isfile(absolute):
        result["error"] = "文件不存在"
        _VERIFY_CACHE[cache_key] = dict(result)
        return result
    if not IS_WINDOWS:
        result["status"] = "invalid"
        result["error"] = "仅支持 Windows 平台"
        _VERIFY_CACHE[cache_key] = dict(result)
        return result

    try:
        libs = _load_libs()
    except Exception as exc:  # noqa: BLE001 - DLL 加载失败降级
        result["status"] = "invalid"
        result["error"] = f"无法加载 wintrust.dll: {exc}"
        _VERIFY_CACHE[cache_key] = dict(result)
        return result

    file_info = _WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = absolute
    file_info.hFile = None
    file_info.pgKnownSubject = None

    trust_data = _WINTRUST_DATA()
    trust_data.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    trust_data.dwUIChoice = _WTD_UI_NONE
    trust_data.fdwRevocationChecks = _WTD_REVOKE_NONE
    trust_data.dwUnionChoice = _WTD_CHOICE_FILE
    trust_data.pUnion = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
    trust_data.dwStateAction = _WTD_STATEACTION_VERIFY
    trust_data.dwProvFlags = _WTD_CACHE_ONLY_URL_RETRIEVAL
    trust_data.dwUIContext = 0

    signer: str | None = None
    try:
        hresult = int(
            libs["wintrust"].WinVerifyTrust(
                None,
                ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(trust_data),
            )
        )
        code = hresult & 0xFFFFFFFF
        if code == 0:
            result["status"] = "valid"
            result["via"] = "embedded"
            signer = _extract_signer(trust_data.hWVTStateData)
            result["signer"] = signer
        elif code in _UNSIGNED_CODES:
            result["status"] = "unsigned"
            result["error"] = _code_message(code, "文件没有数字签名")
        elif code in _REVOCATION_OFFLINE_CODES:
            # 离线环境无法确认吊销状态：按签名有效处理，只记录提示
            result["status"] = "valid"
            result["via"] = "embedded"
            signer = _extract_signer(trust_data.hWVTStateData)
            result["signer"] = signer
            result["error"] = _code_message(code, "吊销状态无法校验，已按有效处理")
        else:
            result["status"] = "invalid"
            result["via"] = "embedded"
            result["error"] = _code_message(code, "签名无效")
    finally:
        # 无论成功失败都要关闭状态句柄，避免句柄泄漏
        _close_wintrust_state(libs, trust_data)

    # 没有嵌入签名时，用目录签名（catalog）复验；Windows 系统文件大多只有目录签名
    if result["status"] == "unsigned":
        catalog_result = _catalog_verify(absolute)
        if catalog_result:
            catalog_status = catalog_result.get("status")
            if catalog_status in ("valid", "invalid"):
                result = catalog_result
            elif catalog_result.get("error"):
                prefix = result.get("error") or ""
                result["error"] = f"{prefix}；目录签名：{catalog_result['error']}"

    _VERIFY_CACHE[cache_key] = dict(result)
    return result


def pe_metadata(path: Any) -> dict[str, Any]:
    """用 pefile 提取 PE 资源版本信息（仅元数据，不参与验签）。

    Returns:
        包含 ``OriginalFilename`` / ``CompanyName`` / ``FileDescription`` /
        ``FileVersion`` / ``InternalName`` / ``ProductName`` 的 dict，
        非 PE 或解析失败时返回空 dict。
    """
    absolute = _abs_path(path)
    if not absolute:
        return {}
    cache_key = os.path.normcase(absolute)
    if cache_key in _PE_CACHE:
        return dict(_PE_CACHE[cache_key])

    metadata: dict[str, Any] = {}
    if not os.path.isfile(absolute):
        _PE_CACHE[cache_key] = metadata
        return {}
    try:
        import pefile  # 延迟导入：缺失时签名功能仍可用
    except ImportError:
        _PE_CACHE[cache_key] = metadata
        return {}

    pe = None
    try:
        pe = pefile.PE(absolute, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]]
        )
        strings: dict[str, str] = {}
        for file_info_list in getattr(pe, "FileInfo", None) or []:
            for entry in file_info_list:
                key = getattr(entry, "Key", b"")
                if key != b"StringFileInfo":
                    continue
                for table in getattr(entry, "StringTable", None) or []:
                    for string_key, string_value in table.entries.items():
                        name = string_key.decode("utf-8", "ignore") if isinstance(string_key, bytes) else str(string_key)
                        value = (
                            string_value.decode("utf-8", "ignore")
                            if isinstance(string_value, bytes)
                            else str(string_value)
                        )
                        strings[name] = value.strip()
        for field in ("OriginalFilename", "CompanyName", "FileDescription", "InternalName", "ProductName"):
            if strings.get(field):
                metadata[field] = strings[field]
        version = strings.get("FileVersion")
        fixed_info = getattr(pe, "VS_FIXEDFILEINFO", None)
        if not version and fixed_info:
            try:
                info = fixed_info[0]
                version = "{}.{}.{}.{}".format(
                    info.FileVersionMS >> 16,
                    info.FileVersionMS & 0xFFFF,
                    info.FileVersionLS >> 16,
                    info.FileVersionLS & 0xFFFF,
                )
            except Exception:
                version = None
        if version:
            metadata["FileVersion"] = version
    except Exception:
        metadata = {}
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass

    _PE_CACHE[cache_key] = dict(metadata)
    return metadata


# ---------------------------------------------------------------------------
# 签名者 / 公司名比较
# ---------------------------------------------------------------------------

_PUNCT_RE = re.compile(r"[^0-9a-z\u4e00-\u9fff]+")

_COMPANY_STOPWORDS = {
    "inc",
    "incorporated",
    "ltd",
    "limited",
    "llc",
    "corp",
    "corporation",
    "company",
    "co",
    "gmbh",
    "the",
    "and",
    "of",
    "technologies",
    "technology",
    "software",
    "systems",
    "group",
    "holdings",
    "international",
}
_UNVERIFIED_COMPANY_VALUES = {
    "",
    "-",
    "n/a",
    "na",
    "none",
    "unknown",
    "(not verified)",
    "(verified)",
    "not verified",
    "未验证",
}


def is_microsoft_signer(signer: str | None) -> bool:
    """签名者是否为微软（签名显示名包含 Microsoft）。"""
    return "microsoft" in str(signer or "").lower()


def _company_tokens(value: str | None) -> set[str]:
    raw = _PUNCT_RE.sub(" ", str(value or "").lower())
    return {token for token in raw.split() if token and token not in _COMPANY_STOPWORDS}


def companies_match(claimed: str | None, signer: str | None) -> bool:
    """弱比较"声称的公司"与"签名者"；无法比较时返回 True（不判不符）。"""
    claimed_text = str(claimed or "").strip()
    signer_text = str(signer or "").strip()
    if not claimed_text or claimed_text.lower() in _UNVERIFIED_COMPANY_VALUES:
        return True
    if not signer_text:
        return True
    claimed_norm = " ".join(_PUNCT_RE.sub(" ", claimed_text.lower()).split())
    signer_norm = " ".join(_PUNCT_RE.sub(" ", signer_text.lower()).split())
    if not claimed_norm or not signer_norm:
        return True
    if claimed_norm == signer_norm or claimed_norm in signer_norm or signer_norm in claimed_norm:
        return True
    return bool(_company_tokens(claimed_text) & _company_tokens(signer_text))


# ---------------------------------------------------------------------------
# 系统目录伪装判定
# ---------------------------------------------------------------------------

# SIG_PATH_MASQUERADE 的排除目录：这些位置本来就存放第三方（非微软）驱动/组件，
# "非微软签名 + 系统目录" 在这里是正常现象，不应按伪装上报（否则 NVIDIA/Realtek
# 等驱动会制造大量 HIGH 误报）。实测 Win11 上 System32 下 999 个文件为微软签名，
# 非微软签名的 70 个里 65 个落在下列目录。
_MASQUERADE_EXCLUDED_MARKERS = (
    "\\system32\\driverstore\\",
    "\\syswow64\\driverstore\\",
    "\\system32\\drivers\\",
    "\\syswow64\\drivers\\",
    "\\system32\\spool\\drivers\\",
    "\\syswow64\\spool\\drivers\\",
    "\\system32\\winboplugins\\",
    "\\syswow64\\winboplugins\\",
)


def is_masquerade_excluded(path: Any) -> bool:
    """判断路径是否属于"第三方驱动/组件的正常存放位置"（不进伪装规则）。"""
    normalized = os.path.normcase(os.path.normpath(str(utils.extract_executable(path) or path or "")))
    if not normalized:
        return False
    return any(marker in normalized for marker in _MASQUERADE_EXCLUDED_MARKERS)


# ---------------------------------------------------------------------------
# Finding 生成
# ---------------------------------------------------------------------------


def _build_evidence(target: str, result: dict[str, Any]) -> dict[str, Any]:
    """构造 Finding 证据；PE 元数据只在真的要产出 Finding 时才解析（性能考虑）。"""
    evidence: dict[str, Any] = {
        "path": target,
        "signature": dict(result),
    }
    metadata = pe_metadata(target)
    if metadata:
        evidence["pe"] = metadata
    return evidence


def signature_finding(
    path: Any,
    claimed_company: str | None = None,
    category: str = "Signature",
) -> dict[str, Any] | None:
    """对单个可执行文件做信任判定，返回 Finding 或 None（可信则无 Finding）。

    判定顺序：无签名 → 签名无效 → 系统目录伪装 → 公司名不符。
    """
    result = verify(path)
    status = result.get("status")
    target = _abs_path(path) or str(path or "")
    if status == "missing":
        # 文件不存在不是签名问题，交给上层模块决定是否上报
        return None
    if not utils.is_pe_executable(target):
        # 脚本类文件（.bat/.vbs/.ps1 等）无法用 Authenticode 签名，不产生签名 Finding
        return None

    if status == "unsigned":
        return make_finding(
            "HIGH",
            category,
            target,
            "可执行文件没有数字签名，无法验证来源可信",
            _build_evidence(target, result),
            "SIG_UNSIGNED",
        )

    if status == "invalid":
        return make_finding(
            "HIGH",
            category,
            target,
            f"数字签名无效：{result.get('error') or '证书链校验失败'}",
            _build_evidence(target, result),
            "SIG_INVALID",
        )

    # status == "valid"
    signer = result.get("signer")
    if (
        signer
        and not is_microsoft_signer(signer)
        and utils.is_in_system_dir(target)
        and not is_masquerade_excluded(target)
    ):
        return make_finding(
            "HIGH",
            category,
            target,
            f"非微软签名的文件位于系统目录（签名者：{signer}）",
            _build_evidence(target, result),
            "SIG_PATH_MASQUERADE",
        )
    if signer and claimed_company and not companies_match(claimed_company, signer):
        return make_finding(
            "MEDIUM",
            category,
            target,
            f"签名者与声称的公司不符：签名者={signer}，声称公司={claimed_company}",
            _build_evidence(target, result),
            "SIG_COMPANY_MISMATCH",
        )
    return None

