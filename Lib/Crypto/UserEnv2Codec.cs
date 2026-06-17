using System;
using System.Globalization;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// user_env2 (SE.ues) 编解码 — 逆向自 libpdd_secure.so (sub_12CF00 加密 + sub_12D43C base64)。
    ///
    /// 公式:
    ///   user_env2 = Base64_std( TEA_CBC变体( ZeroPad8( 明文JSON ) ) )   (去 '=' 填充)
    ///
    /// ★ 明文 JSON 是"可变 schema"(取决于采集状态), 字段固定顺序:
    ///   [ "4" ] [ "8" ] [ "an" ]  "id" "ts" "seq"  [ "pk" ]  "ver"  [ "extra" ]
    ///   (方括号 = 可选; id/ts/seq/ver 恒在)
    ///
    /// 实测四种真实形态 (均逐字节复刻 PASS, 见 scripts/verify_ue2_unified.py):
    ///   最小      : {"id","ts","seq","ver"}                                  (CodecTests 旧样本)
    ///   01(sub)   : {"4",...,"id","ts","seq","ver"}                          (含 "4")
    ///   04(all,s1): {"an":0,"id","ts","seq","pk","ver","extra":""}           (含 an/pk/extra)
    ///   06(all,s14): {"4","8","an":8,"id","ts","seq","pk","ver","extra":...}  (全字段)
    ///
    /// 字段语义:
    ///   id   = android_id (★设备绑定 → mock 改 android_id 必须重算)
    ///   ts   = 请求时刻 ms; seq = SE.ues 内部独立自增序号
    ///   pk   = 固定串 QjBR6EXWoRYBbtpXYYDyDoeSs7JlZVy5ZEULw9Zxchs= (密钥句柄?)
    ///   ver  = 2.2.1; an = 采集深度标志 (0/8); extra = libdyncommon 子编码容器 (头 0f c1 00 00, 不含明文 id)
    ///   "8".realtime.content = "0||&lt;HxW&gt;|16515|1" (含分辨率)
    ///
    /// 加密 (TEA 变体 + CBC, sub_12CF00):
    ///   - 8 字节块, 128bit key, 32 轮, sum 初值 0x9E3779B9 (每块重置, 每轮 -= 0x61C88647)
    ///   - IV 常量: v18=0x329CCB1E, v17=0xED12098F; 每块 v18^=w0; v17^=w1; 32轮; 输出链接下块 (CBC)
    ///   - key (a5==0): fe43183287ace60faa9fde1257e17b89; 明文零填充到 8 倍数
    /// </summary>
    public static class UserEnv2Codec
    {
        private const uint Mask = 0xFFFFFFFF;
        private const uint IvV18 = 848835678u;          // 0x329CCB1E
        private static readonly uint IvV17 = unchecked((uint)(-317585009)); // 0xED12098F
        private const uint DeltaStep = 1640531527u;      // 0x61C88647; sum 初值 = (uint)(-DeltaStep) = 0x9E3779B9
        private const uint SumInit = 0x9E3779B9u;

        /// <summary>固定 pk 字段值 (两报文恒同, 疑似某密钥句柄/公钥 base64)。</summary>
        public const string PkConstant = "QjBR6EXWoRYBbtpXYYDyDoeSs7JlZVy5ZEULw9Zxchs=";

        /// <summary>a5==0 的 key (实际路径用)</summary>
        public static readonly byte[] KeyA5_0 = FromHex("fe43183287ace60faa9fde1257e17b89");
        /// <summary>a5==1 的备用 key (本路径未用)</summary>
        public static readonly byte[] KeyA5_1 = FromHex("1ca9efb76ab59b0aa8f79c135f739a8f");

        // ==================== 可变 schema 明文 ====================

        /// <summary>user_env2 明文字段集 (按固定顺序序列化; 可选字段为 null/false 时不输出)。</summary>
        public sealed class Plain
        {
            public bool Include4 = false;                 // "4":{"2":[""],"3":[""]}
            public string? Field8RealtimeContent = null;  // 非 null → "8":{"realtime":"{\"content\":\"<此值>\"}"}
            public int? An = null;                         // 非 null → "an":<值>
            public string Id = "";
            public long Ts;
            public int Seq;
            public bool IncludePk = false;                 // true → "pk":PkConstant
            public string Ver = "2.2.1";
            public string? Extra = null;                   // 非 null → "extra":"<值>" ("" 表示存在但空)
        }

        /// <summary>按固定顺序 [4][8][an] id ts seq [pk] ver [extra] 序列化明文 JSON (紧凑无空格)。</summary>
        public static string BuildPlaintext(Plain f)
        {
            var sb = new StringBuilder(160);
            sb.Append('{');
            bool first = true;
            void Sep() { if (!first) sb.Append(','); first = false; }

            if (f.Include4) { Sep(); sb.Append("\"4\":{\"2\":[\"\"],\"3\":[\"\"]}"); }
            if (f.Field8RealtimeContent != null)
            {
                Sep();
                string inner = "{\"content\":\"" + f.Field8RealtimeContent + "\"}";
                string esc = inner.Replace("\\", "\\\\").Replace("\"", "\\\"");
                sb.Append("\"8\":{\"realtime\":\"").Append(esc).Append("\"}");
            }
            if (f.An.HasValue) { Sep(); sb.Append("\"an\":").Append(f.An.Value.ToString(CultureInfo.InvariantCulture)); }
            Sep(); sb.Append("\"id\":\"").Append(f.Id).Append('"');
            Sep(); sb.Append("\"ts\":").Append(f.Ts.ToString(CultureInfo.InvariantCulture));
            Sep(); sb.Append("\"seq\":").Append(f.Seq.ToString(CultureInfo.InvariantCulture));
            if (f.IncludePk) { Sep(); sb.Append("\"pk\":\"").Append(PkConstant).Append('"'); }
            Sep(); sb.Append("\"ver\":\"").Append(f.Ver).Append('"');
            if (f.Extra != null) { Sep(); sb.Append("\"extra\":\"").Append(f.Extra).Append('"'); }

            sb.Append('}');
            return sb.ToString();
        }

        // —— 各报文形态预设 ——

        /// <summary>最小形态: {"id","ts","seq","ver"} (CodecTests 旧样本 / 兜底)。</summary>
        public static Plain FormMin(string id, long ts, int seq = 0) => new() { Id = id, Ts = ts, Seq = seq };

        /// <summary>01 报文 (meta_type=sub) 形态: 含 "4"。</summary>
        public static Plain Form01(string id, long ts, int seq = 0) => new() { Include4 = true, Id = id, Ts = ts, Seq = seq };

        /// <summary>04 报文 (meta_type=all, scene=1) 形态: an=0 + pk + extra="" (无 4/8)。</summary>
        public static Plain Form04(string id, long ts, int seq) => new() { An = 0, Id = id, Ts = ts, Seq = seq, IncludePk = true, Extra = "" };

        /// <summary>06 报文 (meta_type=all, scene=14) 形态: 4 + 8 + an=8 + pk + extra(libdyncommon 容器)。</summary>
        /// <param name="realtimeContent">"8".realtime.content, 如 "0||1904x1520|16515|1"</param>
        /// <param name="extra">extra 容器值 (复刻基线或真实产出)</param>
        public static Plain Form06(string id, long ts, int seq, string realtimeContent, string extra) => new()
        {
            Include4 = true,
            Field8RealtimeContent = realtimeContent,
            An = 8,
            Id = id,
            Ts = ts,
            Seq = seq,
            IncludePk = true,
            Extra = extra,
        };

        // ==================== 生成 / 解析 ====================

        /// <summary>由字段集生成 user_env2 (base64, 去 '=')。</summary>
        public static string GenerateFrom(Plain f, byte[]? key = null)
        {
            byte[] pt = Encoding.UTF8.GetBytes(BuildPlaintext(f));
            return Convert.ToBase64String(TeaCbcEncrypt(pt, key ?? KeyA5_0)).TrimEnd('=');
        }

        /// <summary>解密 user_env2 (容许去填充的 base64), 返回去零填充后的明文 JSON。</summary>
        public static string Decrypt(string base64, byte[]? key = null)
        {
            string s = base64;
            int mod = s.Length % 4;
            if (mod != 0) s += new string('=', 4 - mod);
            byte[] ct = Convert.FromBase64String(s);
            byte[] pt = TeaCbcDecrypt(ct, key ?? KeyA5_0);
            int end = pt.Length;
            while (end > 0 && pt[end - 1] == 0) end--;
            return Encoding.UTF8.GetString(pt, 0, end);
        }

        // ==================== 向后兼容 (旧签名, 最小形态) ====================

        /// <summary>[兼容] 组装最小形态明文 {"id","ts","seq","ver"}。</summary>
        public static string BuildPlaintext(string androidId, long tsMs, int seq = 0, string ver = "2.2.1")
            => BuildPlaintext(new Plain { Id = androidId, Ts = tsMs, Seq = seq, Ver = ver });

        /// <summary>[兼容] 由 android_id/ts 直接生成最小形态 user_env2。</summary>
        public static string Generate(string androidId, long tsMs, int seq = 0, string ver = "2.2.1", byte[]? key = null)
            => GenerateFrom(new Plain { Id = androidId, Ts = tsMs, Seq = seq, Ver = ver }, key);

        // ==================== TEA-CBC 变体 ====================

        /// <summary>TEA 变体 + CBC 加密, 明文零填充到 8 的倍数。</summary>
        public static byte[] TeaCbcEncrypt(byte[] plaintext, byte[]? key = null)
        {
            uint[] k = KeyWords(key ?? KeyA5_0);
            int padded = (plaintext.Length + 7) & ~7;
            byte[] buf = new byte[padded];
            Array.Copy(plaintext, buf, plaintext.Length);

            uint v18 = IvV18, v17 = IvV17;
            byte[] outp = new byte[padded];
            for (int b = 0; b < padded / 8; b++)
            {
                v18 = (v18 ^ ReadLE32(buf, 8 * b)) & Mask;
                v17 = (v17 ^ ReadLE32(buf, 8 * b + 4)) & Mask;
                uint sum = SumInit;
                for (int r = 0; r < 32; r++)
                {
                    v18 = unchecked(v18 + (((k[0] + ((v17 << 4) & Mask)) & Mask)
                                          ^ ((v17 + sum) & Mask)
                                          ^ ((k[1] + (v17 >> 5)) & Mask))) & Mask;
                    v17 = unchecked(v17 + (((k[2] + ((v18 << 4) & Mask)) & Mask)
                                          ^ ((sum + v18) & Mask)
                                          ^ ((k[3] + (v18 >> 5)) & Mask))) & Mask;
                    sum = unchecked(sum - DeltaStep) & Mask;
                }
                WriteLE32(outp, 8 * b, v18);
                WriteLE32(outp, 8 * b + 4, v17);
            }
            return outp;
        }

        /// <summary>TEA 变体 + CBC 解密 (TeaCbcEncrypt 的逆)。返回填充后长度的明文 (调用方去零填充)。</summary>
        public static byte[] TeaCbcDecrypt(byte[] ct, byte[]? key = null)
        {
            uint[] k = KeyWords(key ?? KeyA5_0);
            uint prev18 = IvV18, prev17 = IvV17;
            byte[] outp = new byte[ct.Length];
            for (int b = 0; b < ct.Length / 8; b++)
            {
                uint c0 = ReadLE32(ct, 8 * b);
                uint c1 = ReadLE32(ct, 8 * b + 4);
                uint v18 = c0, v17 = c1;
                for (int i = 31; i >= 0; i--)
                {
                    uint sum = unchecked(SumInit - (uint)i * DeltaStep) & Mask;
                    v17 = unchecked(v17 - (((k[2] + ((v18 << 4) & Mask)) & Mask)
                                          ^ ((sum + v18) & Mask)
                                          ^ ((k[3] + (v18 >> 5)) & Mask))) & Mask;
                    v18 = unchecked(v18 - (((k[0] + ((v17 << 4) & Mask)) & Mask)
                                          ^ ((v17 + sum) & Mask)
                                          ^ ((k[1] + (v17 >> 5)) & Mask))) & Mask;
                }
                WriteLE32(outp, 8 * b, (v18 ^ prev18) & Mask);
                WriteLE32(outp, 8 * b + 4, (v17 ^ prev17) & Mask);
                prev18 = c0; prev17 = c1;
            }
            return outp;
        }

        // ==================== 辅助 ====================

        private static uint[] KeyWords(byte[] key)
            => new[] { ReadLE32(key, 0), ReadLE32(key, 4), ReadLE32(key, 8), ReadLE32(key, 12) };

        private static uint ReadLE32(byte[] b, int o)
            => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

        private static void WriteLE32(byte[] b, int o, uint v)
        {
            b[o] = (byte)v; b[o + 1] = (byte)(v >> 8);
            b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24);
        }

        private static byte[] FromHex(string hex)
        {
            byte[] r = new byte[hex.Length / 2];
            for (int i = 0; i < r.Length; i++)
                r[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber);
            return r;
        }
    }
}
