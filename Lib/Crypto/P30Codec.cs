using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// p30 生成实现 — 逆向自 libpdd_secure.so (SecureNative.alm → sub_6E19C → sub_18DAF4)
    ///
    /// 公式 (报文最终 p30):
    ///   p30 = UrlEncode( Base64_std( RC4_std( UrlEncode(风险应用列表), key ) ) )   (base64 去 '=')
    ///   风险应用列表 = "包名:检测时间戳ms;包名:时间戳;..."
    ///
    /// - 语义 = 设备上检测到的 hook/风险应用清单 (反检测字段, 非设备指纹/无 android_id)。
    ///   样本明文 = "com.zhenxi.hunter:1773686850901;" (hunter = hook 框架)。
    /// - RC4 = 标准 RC4 (sub_18DAF4, 同 p49/p125), key = ASCII "a7OpixY4xQc1eT2v" (16字节)。
    /// - 内层 UrlEncode: ':' → %3A, ';' → %3B; 外层 Java za2.a.e 对 base64 串再 UrlEncode (转义 +/=)。
    /// - mock 干净设备: 风险列表应为空, 不能复刻样本 (否则等于上报装了 hunter)。
    ///
    /// 验证: RC4 对称, 解密样本密文得明文; 正向重建 base64 与样本逐字节一致 (scripts/p30_codec.py)。
    /// </summary>
    public static class P30Codec
    {
        /// <summary>p30 专用 RC4 key (硬编码, 由 sub_A1428(17,17,16) 运行时解出)</summary>
        public static readonly byte[] Rc4Key = Encoding.ASCII.GetBytes("a7OpixY4xQc1eT2v");

        /// <summary>风险应用列表项</summary>
        public readonly record struct RiskApp(string Package, long DetectTimeMs);

        /// <summary>把风险应用项拼成明文: "pkg:ts;pkg:ts;"</summary>
        public static string BuildRiskList(IEnumerable<RiskApp> apps)
        {
            var sb = new StringBuilder();
            foreach (var a in apps)
                sb.Append(a.Package).Append(':').Append(a.DetectTimeMs).Append(';');
            return sb.ToString();
        }

        /// <summary>native 内部产出: Base64_std(RC4(UrlEncode(riskList))) (去 '=')。</summary>
        public static string GenBase64(string riskListPlain, byte[]? key = null)
        {
            string enc = UrlEncode(riskListPlain);
            byte[] ct = Rc4(key ?? Rc4Key, Encoding.ASCII.GetBytes(enc));
            return Convert.ToBase64String(ct).TrimEnd('=');
        }

        /// <summary>报文里的最终 p30 (Java za2.a.e 对 base64 串再 UrlEncode)。</summary>
        public static string GenReportField(string riskListPlain, byte[]? key = null)
            => UrlEncode(GenBase64(riskListPlain, key));

        /// <summary>解密 p30 base64 密文 → 明文 (UrlEncode 后的风险列表)。用于验证/分析。</summary>
        public static string DecryptBase64(string p30Base64, byte[]? key = null)
        {
            string padded = p30Base64.Replace("%2B", "+").Replace("%2F", "/").Replace("%3D", "=");
            int mod = padded.Length % 4;
            if (mod != 0) padded += new string('=', 4 - mod);
            byte[] ct = Convert.FromBase64String(padded);
            byte[] pt = Rc4(key ?? Rc4Key, ct);
            return Encoding.ASCII.GetString(pt);
        }

        // ==================== 标准 RC4 ====================

        public static byte[] Rc4(byte[] key, byte[] data)
        {
            byte[] s = new byte[256];
            for (int i = 0; i < 256; i++) s[i] = (byte)i;
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i % key.Length]) & 0xFF;
                (s[i], s[j]) = (s[j], s[i]);
            }
            byte[] outp = new byte[data.Length];
            int x = 0, y = 0;
            for (int n = 0; n < data.Length; n++)
            {
                x = (x + 1) & 0xFF;
                y = (y + s[x]) & 0xFF;
                (s[x], s[y]) = (s[y], s[x]);
                outp[n] = (byte)(data[n] ^ s[(s[x] + s[y]) & 0xFF]);
            }
            return outp;
        }

        // ==================== URL 编码 (与 Java URLEncoder.encode UTF-8 对齐) ====================

        /// <summary>
        /// 复刻 Java URLEncoder.encode(s,"UTF-8"): 保留 A-Za-z0-9 与 - _ . *,
        /// 空格→'+', 其余字节 → %XX (大写十六进制)。
        /// </summary>
        public static string UrlEncode(string s)
        {
            var sb = new StringBuilder();
            foreach (byte b in Encoding.UTF8.GetBytes(s))
            {
                char c = (char)b;
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '*')
                    sb.Append(c);
                else if (c == ' ')
                    sb.Append('+');
                else
                    sb.Append('%').Append(b.ToString("X2", CultureInfo.InvariantCulture));
            }
            return sb.ToString();
        }
    }
}
