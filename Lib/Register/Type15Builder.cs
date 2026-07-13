using System.Text;
using PddLib.Crypto;

namespace PddLib.Register
{
    /// <summary>
    /// data_type=15 报文 es 字段的明文构造 + 加密 (SecureNative.dsi 离线复刻)。
    ///
    /// 流程: 组装 es 明文 JSON (18 字段, 反篡改/环境检测集) → <see cref="Type15Codec.Encode"/>
    ///       (RC4 keystream XOR + base64) → es 字符串。
    /// 明文内 5 个加密子blob (p74/p75/p84/p93/p98) 各自 base64(明文 XOR 逐字段keystream),
    /// keystream 来自 <see cref="Type15Baseline"/>。整份 es 无非对称签名 → 完全可 mock。
    ///
    /// 字段序/类型严格复刻真机 (docs 19): p61/p82/p83/p131 是整数(无引号), 其余带引号;
    /// base64 子blob 里的 '/' '+' **不转义** (真机内层 es JSON 原样)。
    /// 默认 <see cref="Type15Options"/> 逐字节复刻 report_03 干净样本。
    /// </summary>
    public static class Type15Builder
    {
        /// <summary>组装 es 内层明文 JSON (加密前)。</summary>
        public static string BuildEsPlaintext(Type15Options o)
        {
            var sb = new StringBuilder(1024);
            sb.Append('{');
            sb.Append("\"p61\":").Append(o.ReportTs).Append(',');            // int

            sb.Append("\"p62\":{");
            for (int i = 0; i < o.P62.Length; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append('"').Append(i).Append("\":\"").Append(o.P62[i]).Append('"');
            }
            sb.Append("},");

            sb.Append("\"p63\":\"").Append(o.P63).Append("\",");
            sb.Append("\"p64\":\"").Append(o.P64).Append("\",");
            sb.Append("\"p69\":\"").Append(o.P69).Append("\",");
            sb.Append("\"p70\":\"").Append(o.P70).Append("\",");
            sb.Append("\"p71\":\"").Append(o.P71).Append("\",");
            sb.Append("\"p73\":\"").Append(o.P73).Append("\",");
            sb.Append("\"p74\":\"").Append(Type15Codec.EncodeSubBlob(o.P74Plain, Type15Baseline.KsP74)).Append("\",");
            sb.Append("\"p75\":\"").Append(Type15Codec.EncodeSubBlob(o.P75Plain, Type15Baseline.KsP75)).Append("\",");
            sb.Append("\"p82\":").Append(o.P82).Append(',');                 // int
            sb.Append("\"p83\":").Append(o.P83).Append(',');                 // int
            sb.Append("\"p84\":\"").Append(Type15Codec.EncodeSubBlob(o.P84Plain, Type15Baseline.KsP84)).Append("\",");
            sb.Append("\"p93\":\"").Append(Type15Codec.EncodeSubBlob(o.P93Plain, Type15Baseline.KsP93)).Append("\",");
            sb.Append("\"p94\":\"").Append(o.P94).Append("\",");
            sb.Append("\"p97\":\"").Append(o.InstallTs).Append("\",");
            sb.Append("\"p98\":\"").Append(Type15Codec.EncodeSubBlob(o.P98Plain, Type15Baseline.KsP98)).Append('"');
            if (o.IncludeP131)                                               // dv=19 才有 p131; dv=18 无
                sb.Append(",\"p131\":").Append(o.P131);                      // int
            sb.Append('}');
            return sb.ToString();
        }

        /// <summary>构造 es 字段值 (base64(明文 XOR RC4-keystream))。</summary>
        public static string BuildEs(Type15Options o) => Type15Codec.Encode(BuildEsPlaintext(o));

        /// <summary>默认参数构造 (逐字节复刻 report_03)。</summary>
        public static string BuildEs() => BuildEs(new Type15Options());
    }

    /// <summary>
    /// es 明文字段参数。默认值 = report_03 干净基线 (直接 new 即复刻)。
    /// mock 时覆盖 <see cref="ReportTs"/>/<see cref="InstallTs"/> 及各检测字段。
    /// ⚠ 子blob 明文长度须 ≤ 对应 keystream 长度 (p74 63B/p75 117B/p84·p93 15B/p98 128B)。
    /// </summary>
    public sealed class Type15Options
    {
        /// <summary>dynamic-so 版本: 19=含 p131(18字段), 18=无 p131(17字段)。默认 19。</summary>
        public int Dv = 19;
        /// <summary>是否输出 p131 (dv≥19)。</summary>
        public bool IncludeP131 => Dv >= 19;
        public long ReportTs = Type15Baseline.ReportTsBaseline;   // p61 (ms)
        public long InstallTs = Type15Baseline.InstallTsBaseline; // p97 (ms)
        public string[] P62 = (string[])Type15Baseline.P62.Clone();
        public string P63 = Type15Baseline.P63;
        public string P64 = Type15Baseline.P64;
        public string P69 = Type15Baseline.P69;
        public string P70 = Type15Baseline.P70;
        public string P71 = Type15Baseline.P71;
        public string P73 = Type15Baseline.P73;
        public long P82 = Type15Baseline.P82;
        public long P83 = Type15Baseline.P83;
        public string P94 = Type15Baseline.P94;
        public int P131 = Type15Baseline.P131;
        public string P74Plain = Type15Baseline.P74Plain;   // 组件工厂类名
        public string P75Plain = Type15Baseline.P75Plain;   // base.apk 路径
        public string P84Plain = Type15Baseline.P84Plain;   // "{ts}_{n}"
        public string P93Plain = Type15Baseline.P93Plain;
        public string P98Plain = Type15Baseline.P98Plain;   // 检测记录
    }
}
