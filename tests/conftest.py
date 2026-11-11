# -*- coding: utf-8 -*-
"""pytest 全局隔离（V1.5）。

``core.whitelist.load_whitelist()`` 会合并用户级 ``config.json`` 的信任名单
（这是 GUI"信任此项"生效的必要机制）。若开发机/CI 上恰好存在真实用户配置，
历史用例（例如 ``tests/test_core_split.py`` 的合成 Finding）可能被用户信任项
意外降级，导致"本机绿、别人红"。这里统一把 ``TAMPERSCAN_CONFIG_DIR`` 指向
会话级临时目录，保证测试永远不读写真实 ``%APPDATA%\\TamperScan``。
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core import config  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _isolate_tamper_scan_user_config(tmp_path_factory: pytest.TempPathFactory):
    previous = os.environ.get(config.ENV_CONFIG_DIR)
    directory = tmp_path_factory.mktemp("tamper_scan_user_config")
    os.environ[config.ENV_CONFIG_DIR] = str(directory)
    try:
        yield directory
    finally:
        if previous is None:
            os.environ.pop(config.ENV_CONFIG_DIR, None)
        else:
            os.environ[config.ENV_CONFIG_DIR] = previous
