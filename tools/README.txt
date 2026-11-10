TamperScan 外部工具目录
======================

本目录**不包含** autorunsc64.exe。

原因：autorunsc64.exe 属于 Microsoft Sysinternals 工具，其许可不允许第三方
再分发（官方 FAQ: https://learn.microsoft.com/en-us/sysinternals/license-faq）。
因此本仓库不提交该二进制文件，.gitignore 已忽略 tools/autorunsc64.exe。

需要 Autoruns 广度扫描时，请自行从微软官方下载并放到本目录：

    官方下载页：https://learn.microsoft.com/sysinternals/downloads/autoruns
    直接下载：  https://download.sysinternals.com/files/Autoruns.zip
    解压后把 Autoruns64.exe 目录下的 autorunsc64.exe 复制到：
        tools/autorunsc64.exe

Sysinternals 工具会定期更新；下载后建议核对文件版本与数字签名（Microsoft）。

缺失时的行为：
    modules/autoruns.py 返回 SKIPPED Finding（AUTORUNS_UNAVAILABLE），
    扫描流程不会中断，其余 14 个模块不受影响。
    因此本项目可以"开箱即用"（无 Autoruns 也能扫描），只是少了广度兜底。

构建注意：
    build.bat 会把本目录（含本 README）一起打包进 exe；若你需要发布内置
    Autoruns 的二进制，请先自行确认符合 Sysinternals 的许可要求。
