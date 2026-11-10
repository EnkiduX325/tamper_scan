/*
 * 内存专用规则：Base64 编码的 .NET 程序集反射加载（T1620）。
 * 与 memory_powershell.yar 分开，便于后续按用途单独调参/停用。
 */
rule Memory_DotNet_Base64_AssemblyLoad
{
    meta:
        description = "进程内存中出现 Base64 解码后 Assembly.Load 反射加载特征"
        scope = "memory"
        confidence = "medium"
        reference = "MITRE T1620"
    strings:
        $load = "Assembly.Load" ascii wide nocase
        $from = "FromBase64String" ascii wide nocase
        $gzip = "GZipStream" ascii wide nocase
        $deflate = "DeflateStream" ascii wide nocase
    condition:
        $load and $from and any of ($gzip, $deflate)
}
