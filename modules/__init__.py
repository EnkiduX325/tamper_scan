"""TamperScan 扫描模块包。

约定：每个模块对外只暴露 ``def scan() -> list[Finding]``，不依赖全局状态，
不吞掉异常以外的控制流；权限不足时返回 SKIPPED Finding 而不是抛异常。
"""
