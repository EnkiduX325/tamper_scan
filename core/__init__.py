"""TamperScan 核心基础设施包。

- ``finding``：统一的 Finding 数据结构与工厂函数
- ``utils``：权限/路径/命令行/白名单等通用工具
- ``signature``（阶段 1）：Authenticode 签名校验
- ``yara_engine``（阶段 6）：YARA 文件/内存扫描封装
- ``baseline``（V1.3）：基线对比（Baseline Diff）与文件哈希增强
"""

__all__ = ["finding", "utils", "baseline"]
