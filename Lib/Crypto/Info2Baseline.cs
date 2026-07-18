using System;
using System.Collections.Generic;
using System.Text;

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
        /// = 0x0a + 去空格/去括号的 /proc/version 串 (267 字节)。
        /// 结构 = release + 中段(builder@host + 编译器工具链) + 版本(#N + 日期)。
        /// </summary>
        public const string KernelValueB64 =
            "CjYuNi44OS1hbmRyb2lkMTUtOC1nMTQyMjBhZTRjZTY1LWFiMTM2ODA1ODItNGtydW5uZXJAcnVu" +
            "bmVydm1nMXN3MUFuZHJvaWQxMTM2ODMwOCwrcGdvLCtib2x0LCtsdG8sK21sZ28sYmFzZWRvbnI1" +
            "MTA5MjhjbGFuZ3ZlcnNpb24xOC4wLjBodHRwczovL2FuZHJvaWQuZ29vZ2xlc291cmNlLmNvbS90" +
            "b29sY2hhaW4vbGx2bS1wcm9qZWN0NDc3NjEwZDRkMGQ5ODhlNjlkYmMzZmFlNGZlODZiZmYzZjA3" +
            "ZjJiNSxMTEQxOC4wLjAjMU1vbkp1bjIzMDc6MzA6NTdVVEMyMDI1";

        /// <summary>kernel idx=0x1d 的原始 value 字节 (基线)。</summary>
        public static byte[] KernelValue => Convert.FromBase64String(KernelValueB64);

        /// <summary>基线 release (= uname release, 设备相关部分)。</summary>
        public const string BaselineRelease = "6.6.89-android15-8-g14220ae4ce65-ab13680582-4k";

        /// <summary>基线版本紧凑串 (#N + 日期, 去空格; 设备相关部分)。</summary>
        public const string BaselineVersionCompact = "#1MonJun2307:30:57UTC2025";

        /// <summary>
        /// KernelValue 中段 = builder@host + 编译器/工具链元数据 (机型无关, 保持模板)。
        /// = release 之后、版本(#N)之前的全部内容。
        /// </summary>
        public const string Middle =
            "runner@runnervmg1sw1Android11368308,+pgo,+bolt,+lto,+mlgo,basedonr510928" +
            "clangversion18.0.0https://android.googlesource.com/toolchain/llvm-project" +
            "477610d4d0d988e69dbc3fae4fe86bff3f07f2b5,LLD18.0.0";

        private static readonly HashSet<string> Machines = new HashSet<string>
        {
            "aarch64", "armv7l", "armv8l", "arm64", "x86_64", "i686", "riscv64"
        };
        private static readonly HashSet<string> SkipVerToks = new HashSet<string>
        {
            "SMP", "PREEMPT", "PREEMPT_DYNAMIC", "PREEMPT_RT"
        };

        /// <summary>用 release + 版本紧凑串组装 KernelValue 原始字节 (0x0a + release + 中段 + 版本)。</summary>
        public static byte[] Compose(string release, string versionCompact)
        {
            byte[] body = Encoding.UTF8.GetBytes(release + Middle + versionCompact);
            var outp = new byte[body.Length + 1];
            outp[0] = 0x0a;
            Array.Copy(body, 0, outp, 1, body.Length);
            return outp;
        }

        /// <summary>
        /// 从设备 uname 串派生 KernelValue: 抽取 release 与 #N+日期, 替换进基线中段模板。
        /// 使 KernelValue 随设备内核版本变化并与 p4(uname) 保持一致; 解析失败时回落基线。
        /// uname 形如: "Linux &lt;node&gt; &lt;release&gt; #N [SMP] [PREEMPT] &lt;date&gt; &lt;machine&gt; [extra]"。
        /// </summary>
        public static byte[] FromUname(string? uname)
        {
            var parsed = ParseUname(uname);
            return parsed == null ? KernelValue : Compose(parsed.Value.release, parsed.Value.versionCompact);
        }

        private static (string release, string versionCompact)? ParseUname(string? uname)
        {
            if (string.IsNullOrWhiteSpace(uname)) return null;
            string[] toks = uname.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            if (toks.Length < 4 || toks[0] != "Linux") return null;
            string release = toks[2];
            int hi = Array.FindIndex(toks, t => t.StartsWith("#"));
            if (hi < 0) return null;
            int mi = toks.Length;
            for (int i = hi + 1; i < toks.Length; i++)
            {
                if (Machines.Contains(toks[i])) { mi = i; break; }
            }
            var sb = new StringBuilder(toks[hi]);
            for (int i = hi + 1; i < mi; i++)
                if (!SkipVerToks.Contains(toks[i])) sb.Append(toks[i]);
            return (release, sb.ToString());
        }
    }
}
