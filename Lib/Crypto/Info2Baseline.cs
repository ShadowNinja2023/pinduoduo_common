using System;

namespace PddLib.Crypto
{
    /// <summary>
    /// info2 (2af anti-token) TLV 字段基线值 (取自 login send_code 样本, Lenovo TB322FC)。
    /// 结构性/机型级字段用于复刻; per-台唯一值 (android_id/时间/随机) 由 DeviceProfile/运行时提供。
    /// 详见 docs/04_device_register/14_info2_antitoken_analysis.md。
    /// </summary>
    public static class Info2Baseline
    {
        /// <summary>
        /// idx=0x1d kernel /proc/version 复合字段的完整 value 字节 (base64)。
        /// = 0x0a + 去空格的 /proc/version 串 (267 字节)。内层结构未完全还原, 按机型复刻基线。
        /// </summary>
        public const string KernelValueB64 =
            "CjYuNi44OS1hbmRyb2lkMTUtOC1nMTQyMjBhZTRjZTY1LWFiMTM2ODA1ODItNGtydW5uZXJAcnVu" +
            "bmVydm1nMXN3MUFuZHJvaWQxMTM2ODMwOCwrcGdvLCtib2x0LCtsdG8sK21sZ28sYmFzZWRvbnI1" +
            "MTA5MjhjbGFuZ3ZlcnNpb24xOC4wLjBodHRwczovL2FuZHJvaWQuZ29vZ2xlc291cmNlLmNvbS90" +
            "b29sY2hhaW4vbGx2bS1wcm9qZWN0NDc3NjEwZDRkMGQ5ODhlNjlkYmMzZmFlNGZlODZiZmYzZjA3" +
            "ZjJiNSxMTEQxOC4wLjAjMU1vbkp1bjIzMDc6MzA6NTdVVEMyMDI1";

        /// <summary>kernel idx=0x1d 的原始 value 字节。</summary>
        public static byte[] KernelValue => Convert.FromBase64String(KernelValueB64);
    }
}
