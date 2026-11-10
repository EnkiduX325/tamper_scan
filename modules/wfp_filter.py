# -*- coding: utf-8 -*-
"""WFP 持久化过滤器检测（EDR Silencer / 防致盲）。

背景
----
EDRSilencer 等工具滥用 Windows Filtering Platform（WFP）：用 ``FwpmFilterAdd0`` 添加
**persistent** 过滤器，按 ``ALE_APP_ID`` 条件阻断 EDR 进程的 IPv4/IPv6 出站连接，
使安全软件无法回传遥测；过滤器写入 BFE 持久化存储后重启依然生效（T1562.001 /
T1685 / T1569.002）。公开样本参考：
- https://github.com/netero1010/EDRSilencer
- https://www.trendmicro.com/en_us/research/24/j/edrsilencer-disrupting-endpoint-security-solutions.html

存储格式（本模块的核心）
------------------------
``HKLM\\SYSTEM\\CurrentControlSet\\Services\\BFE\\Parameters\\Policy\\Persistent\\Filter``
下，每个持久化对象是**以过滤器 GUID 命名的值**，数据为 16 字节头 + NDR 编码的
``BFE_PERSISTENT_OBJECT``（Type=5 表示 Filter）。该格式由 Quarkslab 逆向整理：
https://blog.quarkslab.com/windows-filtering-platform-persistent-state-under-the-hood.html
对象内部是 ``FWPM_FILTER0`` 的 NDR 序列化，字段顺序与当前 SDK ``fwpmtypes.h`` 一致：
filterKey / displayData / flags / providerKey / providerData / layerKey / subLayerKey /
weight / numFilterConditions / filterCondition / action / rawContext / reserved /
filterId / effectiveWeight。

NDR 指针引用位置随版本与内容变化，本模块**不实现通用 NDR 解码器**，而是：

1. 在 blob 内扫描**结构体起点**：已知字段相对偏移为
   ``+0x18 flags``、``+0x28 layerKey``、``+0x38 subLayerKey``、``+0x48 weight.type``、
   ``+0x50 numFilterConditions``、``+0x58 action.type``、``+0x88 filterId``；
   要求 layer/action/flags 同时自洽，多个候选取最高分（容忍不同 Windows 版本的包装偏移）；
2. 用 WFP 权威常量表在 blob 内定位 **condition 记录**
   （fieldKey GUID + matchType + FWP_VALUE0，元素 32 字节），还原远端 IP/端口等条件值；
3. 解析失败不猜测：该 blob 记为"未解析"，最终以 SKIPPED 提示"部分未检查"。

规则
----
- ``WFP_EDR_SILENCER`` HIGH：BLOCK + 出站层（ALE_AUTH_CONNECT / OUTBOUND_TRANSPORT 等）
  + ``ALE_APP_ID`` 条件（EDRSilencer 特征）；
- ``WFP_BLOCK_PUBLIC_IP`` HIGH：BLOCK + 远端地址条件为公网 IPv4；
- ``WFP_BLOCK_REMOTE_PORT`` HIGH：BLOCK + 出站层 + 指定远端端口；
- ``WFP_BLOCK_FILTER`` MEDIUM：其它非系统 BLOCK 过滤器（含"阻断全部出站"）；
- 系统过滤器（子层为 ``FWPM_SUBLAYER_MPSSVC_*``，或 displayData 以 ``@`` 开头）跳过，
  避免把 Windows 防火墙/Defender 的正常规则当攻击；
- ``WFP_FILTER_UNPARSED`` / ``WFP_PARTIAL`` / ``WFP_ACCESS_DENIED`` / ``WFP_SKIPPED``
  为 SKIPPED 降级（未检查 ≠ 安全）。

已知局限
--------
- 必须管理员：BFE ``Policy`` 键只有 Administrators / SYSTEM 可读；
- IPv6 远端地址以 ``FWP_BYTE_ARRAY16`` 指针形式存储，本版不解析（记为 unresolved）；
- 远端 IP 按 WFP 约定为网络字节序（network order）解释；
- NDR 布局跨 Windows 版本可能变化；结构定位失败的过滤器只记 SKIPPED，不误报；
- 攻击者可伪造 displayData 冒充系统过滤器，此时需结合签名/进程审计人工确认。

本模块只读注册表、不调用 WFP API、不执行命令；遍历带条数/体积上限。
"""

from __future__ import annotations

import ipaddress
import uuid
import winreg
from typing import Any

from core import utils
from core.finding import make_finding, make_skipped
from core.utils import truncate

CATEGORY = "WFPFilter"

# 规则编号
RULE_EDR_SILENCER = "WFP_EDR_SILENCER"
RULE_BLOCK_PUBLIC_IP = "WFP_BLOCK_PUBLIC_IP"
RULE_BLOCK_REMOTE_PORT = "WFP_BLOCK_REMOTE_PORT"
RULE_BLOCK_FILTER = "WFP_BLOCK_FILTER"
RULE_UNPARSED = "WFP_FILTER_UNPARSED"
RULE_PARTIAL = "WFP_PARTIAL"
RULE_ACCESS_DENIED = "WFP_ACCESS_DENIED"
RULE_SKIPPED = "WFP_SKIPPED"

_FILTER_KEY = r"SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Filter"
_ROOT_DISPLAY = r"HKLM\SYSTEM\CurrentControlSet\Services\BFE\Parameters\Policy\Persistent\Filter"

# BFE 持久化对象 16 字节头标记（Quarkslab 逆向样本：01 10 08 00 cc cc cc cc + size + 0）
_OBJECT_MARKER = b"\x01\x10\x08\x00"

# 遍历/解析上限
_MAX_ENTRIES = 4096
_MAX_BLOB = 64 * 1024
_MAX_TOTAL_BYTES = 8 * 1024 * 1024
_MAX_CONDITIONS = 256
_MAX_STRINGS = 12

# WFP 常量（来自 Win32 元数据 / fwpmu.h，已与 bfe.dll 内 GUID 交叉核对）
_FLAG_PERSISTENT = 0x00000001

FWP_ACTION_BLOCK = 0x00001001
FWP_ACTION_PERMIT = 0x00001002
FWP_ACTION_CALLOUT_TERMINATING = 0x00005003
FWP_ACTION_CALLOUT_INSPECTION = 0x00006004
FWP_ACTION_CALLOUT_UNKNOWN = 0x00004005
FWP_ACTION_CONTINUE = 0x00002006

_ACTION_NAMES: dict[int, str] = {
    FWP_ACTION_BLOCK: "FWP_ACTION_BLOCK",
    FWP_ACTION_PERMIT: "FWP_ACTION_PERMIT",
    FWP_ACTION_CALLOUT_TERMINATING: "FWP_ACTION_CALLOUT_TERMINATING",
    FWP_ACTION_CALLOUT_INSPECTION: "FWP_ACTION_CALLOUT_INSPECTION",
    FWP_ACTION_CALLOUT_UNKNOWN: "FWP_ACTION_CALLOUT_UNKNOWN",
    FWP_ACTION_CONTINUE: "FWP_ACTION_CONTINUE",
}

FWP_EMPTY = 0
FWP_UINT8 = 1
FWP_UINT16 = 2
FWP_UINT32 = 3
FWP_UINT64 = 4
FWP_BYTE_ARRAY16_TYPE = 11
FWP_BYTE_BLOB_TYPE = 12
FWP_UNICODE_STRING_TYPE = 17
FWP_RANGE_TYPE = 258

_DATA_TYPE_NAMES: dict[int, str] = {
    0: "FWP_EMPTY",
    1: "FWP_UINT8",
    2: "FWP_UINT16",
    3: "FWP_UINT32",
    4: "FWP_UINT64",
    5: "FWP_INT8",
    6: "FWP_INT16",
    7: "FWP_INT32",
    8: "FWP_INT64",
    9: "FWP_FLOAT",
    10: "FWP_DOUBLE",
    11: "FWP_BYTE_ARRAY16",
    12: "FWP_BYTE_BLOB",
    13: "FWP_SID",
    14: "FWP_SECURITY_DESCRIPTOR",
    15: "FWP_TOKEN_INFORMATION",
    16: "FWP_TOKEN_ACCESS_INFORMATION",
    17: "FWP_UNICODE_STRING",
    18: "FWP_BYTE_ARRAY6",
    256: "FWP_V4_ADDR_MASK",
    257: "FWP_V6_ADDR_MASK",
    258: "FWP_RANGE",
}

_MATCH_NAMES: dict[int, str] = {
    0: "FWP_MATCH_EQUAL",
    1: "FWP_MATCH_GREATER",
    2: "FWP_MATCH_LESS",
    3: "FWP_MATCH_GREATER_OR_EQUAL",
    4: "FWP_MATCH_LESS_OR_EQUAL",
    5: "FWP_MATCH_RANGE",
    6: "FWP_MATCH_FLAGS_ALL_SET",
    7: "FWP_MATCH_FLAGS_ANY_SET",
    8: "FWP_MATCH_FLAGS_NONE_SET",
    9: "FWP_MATCH_EQUAL_CASE_INSENSITIVE",
    10: "FWP_MATCH_NOT_EQUAL",
    11: "FWP_MATCH_PREFIX",
    12: "FWP_MATCH_NOT_PREFIX",
}

# 层 GUID -> (name, direction)：出站/入站用于判定"回传被阻断"的方向
_LAYER_GUIDS: dict[str, tuple[str, str]] = {
    "c38d57d1-05a7-4c33-904f-7fbceee60e82": ("FWPM_LAYER_ALE_AUTH_CONNECT_V4", "outbound"),
    "4a72393b-319f-44bc-84c3-ba54dcb3b6b4": ("FWPM_LAYER_ALE_AUTH_CONNECT_V6", "outbound"),
    "c6e63c8c-b784-4562-aa7d-0a67cfcaf9a3": ("FWPM_LAYER_ALE_CONNECT_REDIRECT_V4", "outbound"),
    "587e54a7-8046-42ba-a0aa-b716250fc7fd": ("FWPM_LAYER_ALE_CONNECT_REDIRECT_V6", "outbound"),
    "09e61aea-d214-46e2-9b21-b26b0b2f28c8": ("FWPM_LAYER_OUTBOUND_TRANSPORT_V4", "outbound"),
    "e1735bde-013f-4655-b351-a49e15762df0": ("FWPM_LAYER_OUTBOUND_TRANSPORT_V6", "outbound"),
    "1247d66d-0b60-4a15-8d44-7155d0f53a0c": ("FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4", "outbound"),
    "55a650e1-5f0a-4eca-a653-88f53b26aa8c": ("FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6", "outbound"),
    "74365cce-ccb0-401a-bfc1-b89934ad7e15": ("FWPM_LAYER_ALE_RESOURCE_RELEASE_V4", "outbound"),
    "f4e5ce80-edcc-4e13-8a2f-b91454bb057b": ("FWPM_LAYER_ALE_RESOURCE_RELEASE_V6", "outbound"),
    "e1cd9fe7-f4b5-4273-96c0-592e487b8650": ("FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4", "inbound"),
    "a3b42c97-9f04-4672-b87e-cee9c483257f": ("FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6", "inbound"),
    "5926dfc8-e3cf-4426-a283-dc393f5d0f9d": ("FWPM_LAYER_INBOUND_TRANSPORT_V4", "inbound"),
    "634a869f-fc23-4b90-b0c1-bf620a36ae6f": ("FWPM_LAYER_INBOUND_TRANSPORT_V6", "inbound"),
    "88bb5dad-76d7-4227-9c71-df0a3ed7be7e": ("FWPM_LAYER_ALE_AUTH_LISTEN_V4", "inbound"),
    "7ac9de24-17dd-4814-b4bd-a9fbc95a321b": ("FWPM_LAYER_ALE_AUTH_LISTEN_V6", "inbound"),
    "3b89653c-c170-49e4-b1cd-e0eeeee19a3e": ("FWPM_LAYER_STREAM_V4", "unknown"),
    "47c9137a-7ec4-46b3-b6e4-48e926b1eda4": ("FWPM_LAYER_STREAM_V6", "unknown"),
    "3d08bf4e-45f6-4930-a922-417098e20027": ("FWPM_LAYER_DATAGRAM_DATA_V4", "unknown"),
    "fa45fe2f-3cba-4427-87fc-57b9a4b10d00": ("FWPM_LAYER_DATAGRAM_DATA_V6", "unknown"),
    "af80470a-5596-4c13-9992-539e6fe57967": ("FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4", "unknown"),
    "7021d2b3-dfa4-406e-afeb-6afaf7e70efd": ("FWPM_LAYER_ALE_FLOW_ESTABLISHED_V6", "unknown"),
}

# 系统（Windows Firewall / Defender 等）使用的内置子层；出现在这些子层上的过滤器不算攻击
_MS_SUBLAYER_GUIDS: dict[str, str] = {
    "b3cdd441-af90-41ba-a745-7c6008ff2300": "FWPM_SUBLAYER_MPSSVC_WSH",
    "b3cdd441-af90-41ba-a745-7c6008ff2301": "FWPM_SUBLAYER_MPSSVC_WF",
    "b3cdd441-af90-41ba-a745-7c6008ff2302": "FWPM_SUBLAYER_MPSSVC_QUARANTINE",
    "ffe221c3-92a8-4564-a59f-dafb70756020": "FWPM_SUBLAYER_MPSSVC_APP_ISOLATION",
    "09a47e38-fa97-471b-b123-18bcd7e65071": "FWPM_SUBLAYER_MPSSVC_EDP",
    "1ec6c7e1-fdd9-478a-b55f-ff8ba1d2c17d": "FWPM_SUBLAYER_MPSSVC_TENANT_RESTRICTIONS",
    "eebecc03-ced4-4380-819a-2734397b2b74": "FWPM_SUBLAYER_UNIVERSAL",
}

# 关注的条件 GUID（其余 GUID 不解析，避免把无关字段错当条件）
_CONDITION_GUIDS: dict[str, str] = {
    "b235ae9a-1d64-49b8-a44c-5ff3d9095045": "FWPM_CONDITION_IP_REMOTE_ADDRESS",
    "1febb610-3bcc-45e1-bc36-2e067e2cb186": "FWPM_CONDITION_IP_REMOTE_ADDRESS_V4",
    "246e1d8c-8bee-4018-9b98-31d4582f3361": "FWPM_CONDITION_IP_REMOTE_ADDRESS_V6",
    "2d79133b-b390-45c6-8699-acaceaafed33": "FWPM_CONDITION_IP_DESTINATION_ADDRESS",
    "ae96897e-2e94-4bc9-b313-b27ee80e574d": "FWPM_CONDITION_IP_SOURCE_ADDRESS",
    "d9ee00de-c1ef-4617-bfe3-ffd8f5a08957": "FWPM_CONDITION_IP_LOCAL_ADDRESS",
    "03a629cb-6e52-49f8-9c41-5709633c09cf": "FWPM_CONDITION_IP_LOCAL_ADDRESS_V4",
    "2381be84-7524-45b3-a05b-1e637d9c7a6a": "FWPM_CONDITION_IP_LOCAL_ADDRESS_V6",
    "c35a604d-d22b-4e1a-91b4-68f674ee674b": "FWPM_CONDITION_IP_REMOTE_PORT",
    "ce6def45-60fb-4a7b-a304-af30a117000e": "FWPM_CONDITION_IP_DESTINATION_PORT",
    "0c1ba1af-5765-453f-af22-a8f791ac775b": "FWPM_CONDITION_IP_LOCAL_PORT",
    "a6afef91-3df4-4730-a214-f5426aebf821": "FWPM_CONDITION_IP_SOURCE_PORT",
    "3971ef2b-623e-4f9a-8cb1-6e79b806b9a7": "FWPM_CONDITION_IP_PROTOCOL",
    "d78e1e87-8644-4ea5-9437-d809ecefc971": "FWPM_CONDITION_ALE_APP_ID",
    "0e6cd086-e1fb-4212-842f-8a9f993fb3f6": "FWPM_CONDITION_ALE_ORIGINAL_APP_ID",
    "af043a0a-b34d-4f86-979c-c90371af6e66": "FWPM_CONDITION_ALE_USER_ID",
    "b1277b9a-b781-40fc-9671-e5f1b989f34e": "FWPM_CONDITION_ALE_EFFECTIVE_NAME",
    "d024de4d-deaa-4317-9c85-e40ef6e140c3": "FWPM_CONDITION_IMAGE_NAME",
    "632ce23b-5167-435c-86d7-e903684aa80c": "FWPM_CONDITION_FLAGS",
    "8784c146-ca97-44d6-9fd1-19fb1840cbf7": "FWPM_CONDITION_DIRECTION",
}

_REMOTE_ADDRESS_CONDITIONS = frozenset(
    {
        "FWPM_CONDITION_IP_REMOTE_ADDRESS",
        "FWPM_CONDITION_IP_REMOTE_ADDRESS_V4",
        "FWPM_CONDITION_IP_DESTINATION_ADDRESS",
        "FWPM_CONDITION_IP_SOURCE_ADDRESS",
    }
)
_REMOTE_PORT_CONDITIONS = frozenset(
    {"FWPM_CONDITION_IP_REMOTE_PORT", "FWPM_CONDITION_IP_DESTINATION_PORT", "FWPM_CONDITION_IP_SOURCE_PORT"}
)
_APP_CONDITIONS = frozenset({"FWPM_CONDITION_ALE_APP_ID", "FWPM_CONDITION_ALE_ORIGINAL_APP_ID"})

# 结构体字段相对偏移（基于 FWPM_FILTER0 字段顺序 / Quarkslab 解码结果）
_OFF_FLAGS = 0x18
_OFF_PROVIDER_DATA_SIZE = 0x20
_OFF_LAYER_KEY = 0x28
_OFF_SUB_LAYER_KEY = 0x38
_OFF_WEIGHT_TYPE = 0x48
_OFF_NUM_CONDITIONS = 0x50
_OFF_ACTION = 0x58
_OFF_FILTER_ID = 0x88
_MIN_STRUCT_SIZE = 0xA0


def _is_access_denied(exc: BaseException) -> bool:
    return isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5


# ---------------------------------------------------------------------------
# 基础二进制工具（纯函数）
# ---------------------------------------------------------------------------


def _read_u32(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(blob):
        return 0
    return int.from_bytes(blob[offset : offset + 4], "little")


def _guid_str(raw: bytes) -> str:
    """把 Windows GUID 内存布局（bytes_le）转成规范字符串；非法返回空串。"""
    if len(raw) != 16:
        return ""
    try:
        return str(uuid.UUID(bytes_le=raw))
    except (ValueError, AttributeError):
        return ""


def _known_guid(blob: bytes, offset: int, table: dict[str, Any]) -> Any:
    guid = _guid_str(blob[offset : offset + 16])
    return table.get(guid) if guid else None


def _is_public_ipv4(text: str) -> bool:
    """是否公网 IPv4（排除私网/环回/链路本地/组播/保留/CGNAT 等）。"""
    try:
        address = ipaddress.IPv4Address(text)
    except (ipaddress.AddressValueError, ValueError):
        return False
    # 注意：Python 3.10 的 is_global 对组播/保留段可能返回 True，必须显式排除
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_unspecified
        or address.is_reserved
    ):
        return False
    # 运营商级 NAT（100.64.0.0/10，RFC 6598）不是公网可路由地址（部分 Python 版本未归类）
    if address in ipaddress.IPv4Network("100.64.0.0/10"):
        return False
    try:
        return bool(address.is_global)
    except Exception:  # noqa: BLE001 - 老版本 Python 的 ipaddress 兜底
        return True


def _extract_utf16_strings(blob: bytes) -> list[str]:
    """尽力提取 blob 内的 UTF-16LE 可读字符串（displayData / 路径等）。"""
    strings: list[str] = []
    seen: set[str] = set()
    chars: list[str] = []

    def _flush() -> None:
        if len(chars) >= 4:
            text = "".join(chars).strip()
            if text and text not in seen and len(strings) < _MAX_STRINGS:
                seen.add(text)
                strings.append(truncate(text, 200))

    for index in range(0, len(blob) - 1, 2):
        codepoint = blob[index] | (blob[index + 1] << 8)
        if 0x20 <= codepoint <= 0x7E or 0x4E00 <= codepoint <= 0x9FFF:
            chars.append(chr(codepoint))
        else:
            _flush()
            chars = []
    _flush()
    return strings


def _condition_value(blob: bytes, offset: int) -> dict[str, Any]:
    """解析 condition 记录（fieldKey 后 16 字节）里的 matchType / FWP_VALUE0。"""
    match_type = _read_u32(blob, offset + 16)
    value_type = _read_u32(blob, offset + 20)
    # FWP_VALUE0 的 union 需要 8 字节对齐；记录元素起点通常 8 字节对齐
    union_offset = offset + 24
    if union_offset % 8:
        union_offset += 4
    raw_union = blob[union_offset : union_offset + 8]
    if len(raw_union) < 8:
        return {}
    condition: dict[str, Any] = {
        "match_type": match_type,
        "match_name": _MATCH_NAMES.get(match_type, f"match#{match_type}"),
        "value_type": value_type,
        "value_name": _DATA_TYPE_NAMES.get(value_type, f"type#{value_type}"),
        "raw_hex": raw_union.hex(),
    }
    if value_type == FWP_UINT16:
        condition["port"] = int.from_bytes(raw_union[0:2], "little")
    elif value_type == FWP_UINT32:
        # WFP 约定：IPv4 以网络字节序存放在 UINT32
        condition["ipv4"] = str(ipaddress.IPv4Address(raw_union[0:4]))
    elif value_type == FWP_UINT8:
        condition["protocol"] = raw_union[0]
    elif value_type == FWP_UINT64:
        condition["uint64"] = int.from_bytes(raw_union, "little")
    return condition


def _scan_conditions(blob: bytes) -> list[dict[str, Any]]:
    """扫描 blob 中所有已知 condition 记录（GUID 精确匹配，几乎无误报）。"""
    conditions: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for offset in range(0, len(blob) - 31, 4):
        guid = _guid_str(blob[offset : offset + 16])
        name = _CONDITION_GUIDS.get(guid) if guid else None
        if not name:
            continue
        value = _condition_value(blob, offset)
        if not value:
            continue
        if value["match_type"] > 0x100:
            continue
        key = (guid, value["raw_hex"])
        if key in seen:
            continue
        seen.add(key)
        record = {"field_key": guid, "field_name": name}
        record.update(value)
        conditions.append(record)
        if len(conditions) >= _MAX_CONDITIONS:
            break
    return conditions


# ---------------------------------------------------------------------------
# 结构体定位（纯函数）
# ---------------------------------------------------------------------------


def _score_struct(blob: bytes, base: int) -> tuple[int, dict[str, Any]]:
    """给候选结构体起点打分：layer/action/flags 同时自洽才能高分。"""
    score = 0
    info: dict[str, Any] = {}
    if base + _MIN_STRUCT_SIZE > len(blob):
        return -1, info

    layer = _known_guid(blob, base + _OFF_LAYER_KEY, _LAYER_GUIDS)
    if layer:
        score += 4
        info["layer_name"], info["layer_direction"] = layer
        info["layer_key"] = _guid_str(blob[base + _OFF_LAYER_KEY : base + _OFF_LAYER_KEY + 16])

    sub_guid = _guid_str(blob[base + _OFF_SUB_LAYER_KEY : base + _OFF_SUB_LAYER_KEY + 16])
    if sub_guid:
        score += 1
        info["sub_layer_key"] = sub_guid
        info["sub_layer_name"] = _MS_SUBLAYER_GUIDS.get(sub_guid, "")
        if info["sub_layer_name"]:
            score += 2

    flags = _read_u32(blob, base + _OFF_FLAGS)
    if flags & _FLAG_PERSISTENT:
        score += 2
    elif flags == 0:
        score += 1
    if flags > 0xFFFF:
        score -= 3

    action = _read_u32(blob, base + _OFF_ACTION)
    if action in _ACTION_NAMES:
        score += 4
        info["action"] = action
        info["action_name"] = _ACTION_NAMES[action]

    num_conditions = _read_u32(blob, base + _OFF_NUM_CONDITIONS)
    if num_conditions <= 0x200:
        score += 1
        info["num_conditions"] = num_conditions
    else:
        score -= 2

    weight_type = _read_u32(blob, base + _OFF_WEIGHT_TYPE)
    if weight_type <= 0x200:
        score += 1
        info["weight_type"] = weight_type

    provider_size = _read_u32(blob, base + _OFF_PROVIDER_DATA_SIZE)
    if provider_size <= 0x1000:
        score += 1
        info["provider_data_size"] = provider_size

    filter_id = int.from_bytes(blob[base + _OFF_FILTER_ID : base + _OFF_FILTER_ID + 8], "little")
    if filter_id:
        score += 1
        info["filter_id"] = filter_id

    if _read_u32(blob, base + 0x10):  # displayData.name 指针非空
        score += 1

    info["flags"] = flags
    return score, info


def _locate_struct(blob: bytes) -> tuple[int, int, dict[str, Any]]:
    """扫描 16..0x80 的 4 字节对齐候选点，返回 (base, score, info)。"""
    best_base, best_score, best_info = -1, 0, {}
    max_base = min(len(blob) - _MIN_STRUCT_SIZE, 0x80)
    for base in range(0x08, max_base + 1, 4):
        score, info = _score_struct(blob, base)
        if score > best_score:
            best_base, best_score, best_info = base, score, info
    # 必须同时识别出 layer 与 action，才算"结构定位成功"（阈值 12）
    if best_score < 12 or "layer_name" not in best_info or "action" not in best_info:
        return -1, best_score, {}
    return best_base, best_score, best_info


# ---------------------------------------------------------------------------
# 解析与判定（纯函数，便于单元测试）
# ---------------------------------------------------------------------------


def _parse_filter_blob(blob: bytes) -> dict[str, Any]:
    """解析一个持久化过滤器 blob；失败返回 ``struct_found=False``（不抛异常）。"""
    result: dict[str, Any] = {
        "struct_found": False,
        "struct_base": -1,
        "score": 0,
        "header_valid": False,
        "filter_key": "",
        "layer_key": "",
        "layer_name": "",
        "layer_direction": "",
        "sub_layer_key": "",
        "sub_layer_name": "",
        "flags": 0,
        "persistent": False,
        "action": 0,
        "action_name": "",
        "num_conditions": 0,
        "filter_id": 0,
        "weight_type": 0,
        "conditions": [],
        "strings": [],
    }
    if not isinstance(blob, (bytes, bytearray)) or len(blob) < 0x40:
        return result
    blob = bytes(blob)
    result["header_valid"] = blob[:4] == _OBJECT_MARKER
    result["strings"] = _extract_utf16_strings(blob)

    base, score, info = _locate_struct(blob)
    if base < 0:
        result["score"] = score
        return result

    result.update(
        {
            "struct_found": True,
            "struct_base": base,
            "score": score,
            "filter_key": _guid_str(blob[base : base + 16]),
            "flags": int(info.get("flags") or 0),
            "persistent": bool(int(info.get("flags") or 0) & _FLAG_PERSISTENT),
            "action": int(info.get("action") or 0),
            "action_name": str(info.get("action_name") or ""),
            "layer_key": str(info.get("layer_key") or ""),
            "layer_name": str(info.get("layer_name") or ""),
            "layer_direction": str(info.get("layer_direction") or ""),
            "sub_layer_key": str(info.get("sub_layer_key") or ""),
            "sub_layer_name": str(info.get("sub_layer_name") or ""),
            "num_conditions": int(info.get("num_conditions") or 0),
            "filter_id": int(info.get("filter_id") or 0),
            "weight_type": int(info.get("weight_type") or 0),
        }
    )
    result["conditions"] = _scan_conditions(blob)
    return result


def _looks_system(parsed: dict[str, Any]) -> bool:
    """系统/内置过滤器启发式：MPSSVC 子层，或 displayData 为资源字符串（@...）。"""
    if str(parsed.get("sub_layer_name") or "").startswith("FWPM_SUBLAYER_MPSSVC"):
        return True
    return any(str(text).startswith("@") for text in parsed.get("strings") or [])


def _base_evidence(entry: dict[str, Any], parsed: dict[str, Any]) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "value_name": entry.get("name", ""),
        "layout": entry.get("layout", "value"),
        "registry_key": f"{_ROOT_DISPLAY}\\{entry.get('name', '')}",
        "blob_size": len(entry.get("data") or b""),
        "header_valid": parsed.get("header_valid"),
        "parse_score": parsed.get("score"),
        "struct_base": parsed.get("struct_base"),
        "filter_key": parsed.get("filter_key", ""),
        "action": parsed.get("action_name", ""),
        "layer_key": parsed.get("layer_key", ""),
        "layer_name": parsed.get("layer_name", ""),
        "layer_direction": parsed.get("layer_direction", ""),
        "sub_layer_key": parsed.get("sub_layer_key", ""),
        "sub_layer_name": parsed.get("sub_layer_name", ""),
        "flags": parsed.get("flags", 0),
        "persistent_flag": parsed.get("persistent", False),
        "num_conditions": parsed.get("num_conditions", 0),
        "filter_id": parsed.get("filter_id", 0),
        "conditions": parsed.get("conditions", []),
        "display_strings": parsed.get("strings", []),
        "system_like": _looks_system(parsed),
    }
    return evidence


def _analyze_filter(entry: dict[str, Any], parsed: dict[str, Any]) -> list[dict[str, Any]]:
    """对单个已解析过滤器做判定（纯函数）。"""
    if not parsed.get("struct_found") or parsed.get("action") != FWP_ACTION_BLOCK:
        return []
    target = f"{_ROOT_DISPLAY}\\{entry.get('name', '')}"
    evidence = _base_evidence(entry, parsed)
    if _looks_system(parsed):
        return []

    conditions = parsed.get("conditions") or []
    outbound = parsed.get("layer_direction") == "outbound"
    layer_name = parsed.get("layer_name") or "unknown"
    has_app_id = any(condition.get("field_name") in _APP_CONDITIONS for condition in conditions)
    public_ips = sorted(
        {
            condition["ipv4"]
            for condition in conditions
            if condition.get("field_name") in _REMOTE_ADDRESS_CONDITIONS
            and condition.get("ipv4")
            and _is_public_ipv4(condition["ipv4"])
        }
    )
    remote_ports = sorted(
        {
            int(condition["port"])
            for condition in conditions
            if condition.get("field_name") in _REMOTE_PORT_CONDITIONS and condition.get("port") is not None
        }
    )

    findings: list[dict[str, Any]] = []
    if outbound and has_app_id:
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                target,
                (
                    f"持久化 WFP 过滤器在出站层按应用（ALE_APP_ID）阻断连接，符合 EDR Silencer 防致盲特征："
                    f"{layer_name}"
                ),
                dict(evidence),
                RULE_EDR_SILENCER,
            )
        )
    if public_ips:
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                target,
                f"持久化 WFP 阻断过滤器针对公网 IP：{', '.join(public_ips[:5])}（层 {layer_name}）",
                dict(evidence),
                RULE_BLOCK_PUBLIC_IP,
            )
        )
    if outbound and remote_ports:
        findings.append(
            make_finding(
                "HIGH",
                CATEGORY,
                target,
                f"持久化 WFP 阻断过滤器针对出站远端端口：{', '.join(str(port) for port in remote_ports[:8])}"
                f"（层 {layer_name}）",
                dict(evidence),
                RULE_BLOCK_REMOTE_PORT,
            )
        )
    if not findings:
        detail = (
            f"非系统持久化 WFP 阻断过滤器（层 {layer_name}，条件 {len(conditions)} 条），需人工确认是否为安全软件自身规则"
        )
        if not conditions and outbound:
            detail = f"非系统持久化 WFP 过滤器在出站层阻断全部流量（层 {layer_name}），需人工确认"
        findings.append(make_finding("MEDIUM", CATEGORY, target, detail, dict(evidence), RULE_BLOCK_FILTER))
    return findings


# ---------------------------------------------------------------------------
# 注册表采集
# ---------------------------------------------------------------------------


def _read_subkey_blob(hive: int, subkey: str, flags: int) -> bytes | None:
    """兼容变体布局：子键下的 FilterData（或最大 REG_BINARY）作为过滤器 blob。"""
    try:
        with winreg.OpenKey(hive, subkey, 0, flags) as key:
            try:
                value_count = int(winreg.QueryInfoKey(key)[1])
            except OSError:
                return None
            candidates: list[tuple[str, bytes]] = []
            for index in range(value_count):
                try:
                    name, data, value_type = winreg.EnumValue(key, index)
                except OSError:
                    break
                if value_type != winreg.REG_BINARY or not isinstance(data, (bytes, bytearray)) or not data:
                    continue
                candidates.append((str(name), bytes(data)))
            if not candidates:
                return None
            for name, data in candidates:
                if name.lower() == "filterdata":
                    return data
            return max(candidates, key=lambda item: len(item[1]))[1]
    except OSError:
        return None


def _read_persistent_filter_entries(
    hive: int = winreg.HKEY_LOCAL_MACHINE,
    root: str = _FILTER_KEY,
    view_flag: int = winreg.KEY_WOW64_64KEY,
) -> tuple[list[dict[str, Any]], dict[str, Any], str | None]:
    """读取 BFE 持久化 Filter 存储。

    Returns:
        ``(条目列表, 统计, 致命错误)``；条目为
        ``{"name", "layout", "data"}``，致命错误表示根键本身打开失败。
    """
    entries: list[dict[str, Any]] = []
    stats: dict[str, Any] = {
        "values": 0,
        "subkeys": 0,
        "skipped": 0,
        "errors": 0,
        "truncated": 0,
        "fatal_kind": "",
    }
    flags = winreg.KEY_READ | int(view_flag or 0)
    try:
        with winreg.OpenKey(hive, root, 0, flags) as key:
            try:
                subkey_count = int(winreg.QueryInfoKey(key)[0])
                value_count = int(winreg.QueryInfoKey(key)[1])
            except OSError as exc:
                stats["fatal_kind"] = "open_failed" if not _is_access_denied(exc) else "access_denied"
                return entries, stats, "无法读取 Filter 键的元数据"
            for index in range(value_count):
                if len(entries) >= _MAX_ENTRIES:
                    stats["truncated"] += 1
                    break
                try:
                    name, data, value_type = winreg.EnumValue(key, index)
                except OSError:
                    stats["errors"] += 1
                    break
                if value_type != winreg.REG_BINARY or not isinstance(data, (bytes, bytearray)) or not data:
                    stats["skipped"] += 1
                    continue
                payload = bytes(data)
                if len(payload) > _MAX_BLOB:
                    stats["skipped"] += 1
                    continue
                entries.append({"name": str(name), "layout": "value", "data": payload})
                stats["values"] += 1
            for index in range(subkey_count):
                if len(entries) >= _MAX_ENTRIES:
                    stats["truncated"] += 1
                    break
                try:
                    sub_name = winreg.EnumKey(key, index)
                except OSError:
                    stats["errors"] += 1
                    break
                payload = _read_subkey_blob(hive, f"{root}\\{sub_name}", flags)
                if payload is None:
                    stats["skipped"] += 1
                    continue
                if len(payload) > _MAX_BLOB:
                    stats["skipped"] += 1
                    continue
                entries.append({"name": str(sub_name), "layout": "subkey", "data": payload})
                stats["subkeys"] += 1
    except FileNotFoundError:
        stats["fatal_kind"] = "not_found"
    except OSError as exc:
        stats["fatal_kind"] = "access_denied" if _is_access_denied(exc) else "open_failed"
    except Exception:  # noqa: BLE001 - 采集层任何意外都不抛出
        stats["fatal_kind"] = "open_failed"

    kind = stats["fatal_kind"]
    if kind == "access_denied":
        return entries, stats, f"拒绝访问（需要管理员权限）：{_ROOT_DISPLAY}"
    if kind == "not_found":
        return entries, stats, f"注册表键不存在：{_ROOT_DISPLAY}"
    if kind == "open_failed":
        return entries, stats, f"打开注册表键失败：{_ROOT_DISPLAY}"
    return entries, stats, None


# ---------------------------------------------------------------------------
# 对外入口
# ---------------------------------------------------------------------------


def scan() -> list[dict[str, Any]]:
    """扫描 BFE 持久化 WFP 过滤器，返回 ``list[Finding]``。"""
    try:
        entries, stats, fatal = _read_persistent_filter_entries()
        if fatal:
            rule_id = RULE_ACCESS_DENIED if stats.get("fatal_kind") == "access_denied" else RULE_SKIPPED
            return [
                make_skipped(
                    CATEGORY,
                    _ROOT_DISPLAY,
                    f"WFP 持久化过滤器检测无法执行：{fatal}",
                    {"error": stats.get("fatal_kind") or "open_failed", "stats": stats},
                    rule_id,
                )
            ]

        findings: list[dict[str, Any]] = []
        unparsed = 0
        processed_bytes = 0
        for entry in entries:
            payload = entry.get("data") or b""
            if processed_bytes + len(payload) > _MAX_TOTAL_BYTES:
                stats["truncated"] = int(stats.get("truncated") or 0) + 1
                break
            processed_bytes += len(payload)
            try:
                parsed = _parse_filter_blob(payload)
            except Exception:  # noqa: BLE001 - 单个 blob 解析异常不影响其它过滤器
                unparsed += 1
                continue
            if not parsed.get("struct_found"):
                unparsed += 1
                continue
            findings.extend(_analyze_filter(entry, parsed))

        if unparsed:
            findings.append(
                make_skipped(
                    CATEGORY,
                    _ROOT_DISPLAY,
                    f"{unparsed} 个持久化 WFP 过滤器二进制无法解析（NDR 布局可能变化），这些过滤器未检查",
                    {"unparsed": unparsed, "stats": stats},
                    RULE_UNPARSED,
                )
            )
        if int(stats.get("errors") or 0) or int(stats.get("truncated") or 0):
            findings.append(
                make_skipped(
                    CATEGORY,
                    _ROOT_DISPLAY,
                    (
                        "WFP 持久化过滤器部分未完整读取："
                        f"枚举失败 {int(stats.get('errors') or 0)} 个 / 截断 {int(stats.get('truncated') or 0)} 个"
                    ),
                    {"stats": stats},
                    RULE_PARTIAL,
                )
            )
        return utils.apply_whitelist(findings)
    except Exception as exc:  # noqa: BLE001 - 模块级兜底，不中断整体扫描
        return [
            make_skipped(
                CATEGORY,
                _ROOT_DISPLAY,
                f"WFP 持久化过滤器检测异常：{type(exc).__name__}: {exc}",
                {"error": f"{type(exc).__name__}: {exc}"},
                RULE_SKIPPED,
            )
        ]
