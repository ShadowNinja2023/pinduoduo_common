using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace PddLib.H5
{
    /// <summary>
    /// anti_content ("0as...") 纯 C# 脱机编解码器 —— 完整逆向 react_anti_co 的 encode/deflate/ek-va。
    /// 无需 jsdom/浏览器/Node。与 Python 版 (scripts/h5_tools/anti_full_decode.py + anti_encode.py) 等价, 双向逐字节验证。
    ///
    /// 编码链 (react_anti_co.deobf.js ot()/encode@666/ek@527/va@476):
    ///   各采集器 packN() → i.ek(tag,data)/i.va(num) 拼字节 e
    ///   → 帧头 [02 01 00 00 lenHi lenLo] + payload
    ///   → pako.deflate(zlib)  → +f(4B 版本常量=9637a4f0)
    ///   → 自定义 base64 (字母表 <see cref="Alphabet"/> + 每token随机盐 m + budget 置换)  → "0as" 前缀
    ///
    /// - encode = 标准 base64 变体: 盐 m=末字符; budget(v,m): v==63→m; v&gt;=m→v+1; else v (双射可逆)。
    /// - ek: byte0=(tag&lt;&lt;3)|W(1..7) 或 (tag&lt;&lt;3)+va(W)(W&gt;7) 或 仅(tag&lt;&lt;3)(W=0)。值: str=charCode&amp;0xff / num=大端最小字节 / arr=原样。
    /// - va = LEB128 (低7位在前); pbc(tag7/11 的 href hash)=恒 4 字节。
    /// - f 尾部恒 4 字节 ⇒ 解码时 raw[..^4]=deflate流, raw[^4..]=f。
    ///
    /// 字段语义见 docs/05_h5_web_crypto/07。真机 vs mock 差异: tag8屏幕/tag9 id(秒时间戳)/tag15 UA(android前缀)/
    /// tag16·17 nano_fp/tag19 pdd_user_id/tag20 storage/tag23 pdd_vds/tag26 浏览器位(真机0)/tag28 audio(真机2,2)。
    /// </summary>
    public static class AntiContentCodec
    {
        public const string Alphabet = "9240gsB6PftGXnlQTw_pdvz7EekDmuAWCVZ5UF-MSK1IHOchoaxqYyj8Jb3LrNiR";
        public const string Prefix = "0as";
        /// <summary>尾部自算指纹 f (版本常量, 真机/mock 一致)。</summary>
        public static readonly byte[] FTail = new byte[] { 0x96, 0x37, 0xa4, 0xf0 };

        private static readonly int[] Idx = BuildIdx();
        private static int[] BuildIdx()
        {
            var a = new int[128];
            for (int i = 0; i < a.Length; i++) a[i] = -1;
            for (int i = 0; i < Alphabet.Length; i++) a[Alphabet[i]] = i;
            return a;
        }

        // ======================= pack 原语 =======================
        /// <summary>字符串 → 字节 (charCodeAt &amp; 0xff)。</summary>
        public static byte[] Sc(string s)
        {
            var b = new byte[s.Length];
            for (int i = 0; i < s.Length; i++) b[i] = (byte)(s[i] & 0xff);
            return b;
        }

        /// <summary>数值 → 最小大端字节 (abs); 0 → [0]。</summary>
        public static byte[] Nc(long n)
        {
            n = Math.Abs(n);
            if (n == 0) return new byte[] { 0 };
            var tmp = new List<byte>();
            while (n > 0) { tmp.Add((byte)(n & 0xff)); n >>= 8; }
            tmp.Reverse();
            return tmp.ToArray();
        }

        /// <summary>LEB128 varint (低 7 位在前, 高位续标志)。</summary>
        public static byte[] Va(long n)
        {
            var outB = new List<byte>();
            while (true)
            {
                int b = (int)(n & 0x7f);
                n >>= 7;
                if (n != 0) outB.Add((byte)(b | 0x80));
                else { outB.Add((byte)b); break; }
            }
            return outB.ToArray();
        }

        /// <summary>ek 字段头+值。</summary>
        public static byte[] Ek(int tag, byte[]? vb = null)
        {
            vb ??= Array.Empty<byte>();
            int W = vb.Length;
            if (W >= 1 && W <= 7)
            {
                var r = new byte[1 + W];
                r[0] = (byte)((tag << 3) | W);
                Array.Copy(vb, 0, r, 1, W);
                return r;
            }
            if (W == 0) return new byte[] { (byte)(tag << 3) };
            // W > 7
            var head = new byte[] { (byte)(tag << 3) };
            return Concat(head, Va(W), vb);
        }

        private static long ParseVarint(byte[] d, ref int pos)
        {
            int shift = 0; long val = 0;
            while (pos < d.Length)
            {
                byte b = d[pos++];
                val |= (long)(b & 0x7f) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
            }
            return val;
        }

        // ======================= 字段模型 =======================
        public sealed class AntiField
        {
            public int Tag;
            public string? Str;        // 9,12,13,15,16,17,18,19,20,23
            public long? Num;          // 14,21,22
            public List<long> Va = new();  // 7,8,10,26,27,28
            public string? Href;       // 7
            public string? Port;       // 7
            public byte[]? C;          // 7 (this.c, 4B)
            public byte[]? Pbc;        // 11 (4B)
            public byte[]? Raw;        // 行为 1/2/3/4/24/25

            public override string ToString()
            {
                var sb = new StringBuilder($"tag {Tag,3} | ");
                if (Href != null) sb.Append($"href={Href} port='{Port}' c={ToHex(C)}");
                else if (Pbc != null) sb.Append($"pbc={ToHex(Pbc)}");
                else if (Str != null) sb.Append($"str={Str}");
                else if (Num != null) sb.Append($"num={Num}");
                else if (Raw != null) sb.Append($"raw={ToHex(Raw)}");
                if (Va.Count > 0) sb.Append($" va=[{string.Join(",", Va)}]");
                return sb.ToString();
            }
        }

        public sealed class AntiDecoded
        {
            public int SaltM;
            public byte[] Inflated = Array.Empty<byte>();
            public byte[] FTailBytes = Array.Empty<byte>();
            public byte[] Payload = Array.Empty<byte>();   // 帧头后
            public List<AntiField> Fields = new();
        }

        // ======================= 帧 =======================
        public static byte[] Frame(byte[] payload)
        {
            int L = payload.Length;
            var head = new byte[] { 2, 1, 0, 0, (byte)((L >> 8) & 0xff), (byte)(L & 0xff) };
            return Concat(head, payload);
        }

        // ======================= 字段 → payload (PackFields) =======================
        public static byte[] PackFields(IEnumerable<AntiField> fields)
        {
            var outB = new List<byte>();
            void Add(byte[] b) => outB.AddRange(b);
            foreach (var f in fields)
            {
                switch (f.Tag)
                {
                    case 7:
                        {
                            var href = Sc(f.Href ?? "");
                            var port = Sc(f.Port ?? "");
                            Add(Ek(7)); Add(Va(href.Length)); Add(href);
                            Add(Va(port.Length)); Add(port);
                            Add(f.C ?? Array.Empty<byte>());
                            break;
                        }
                    case 8:
                        Add(Ek(8)); foreach (var v in f.Va) Add(Va(v)); break;
                    case 9:
                        Add(Ek(9, Sc(f.Str ?? ""))); break;
                    case 10:
                        Add(Ek(10)); foreach (var v in f.Va) Add(Va(v)); break;
                    case 11:
                        Add(Ek(11)); Add(f.Pbc ?? Array.Empty<byte>()); break;
                    case 12: case 13:
                        Add(Ek(f.Tag, Sc(f.Str ?? ""))); break;
                    case 14:
                        Add(Ek(14, Nc(f.Num ?? 0))); break;
                    case 15:
                        Add(Ek(15, Sc(f.Str ?? ""))); break;
                    case 16: case 17:
                    case 18: case 19: case 20: case 23:
                        Add(Ek(f.Tag, Sc(f.Str ?? ""))); break;
                    case 21: case 22:
                        Add(Ek(f.Tag, Nc(f.Num ?? 0))); break;
                    case 26: case 27:
                        Add(Ek(f.Tag)); foreach (var v in f.Va) Add(Va(v)); break;
                    case 28:
                        Add(Ek(28)); foreach (var v in f.Va) Add(Va(v)); break;
                    case 1: case 2: case 3: case 4: case 24: case 25:
                        Add(Ek(f.Tag, f.Raw ?? Array.Empty<byte>())); break;
                    default:
                        throw new InvalidOperationException($"未知 tag {f.Tag}, 无法重打包");
                }
            }
            return outB.ToArray();
        }

        // ======================= payload → 字段 (ParseFields) =======================
        public static List<AntiField> ParseFields(byte[] payload, out byte[] rest)
        {
            var fields = new List<AntiField>();
            int pos = 0;
            int PeekTag() => pos < payload.Length ? payload[pos] >> 3 : -1;

            (int tag, int low3, byte[] val) ReadEk()
            {
                byte b0 = payload[pos++];
                int tag = b0 >> 3, low3 = b0 & 7;
                int W = low3 != 0 ? low3 : (int)ParseVarint(payload, ref pos);
                var val = new byte[W];
                Array.Copy(payload, pos, val, 0, W); pos += W;
                return (tag, low3, val);
            }

            var behaviorFirst = new HashSet<int> { 1, 2, 24, 25, 4, 3 };
            while (pos < payload.Length && behaviorFirst.Contains(PeekTag()))
            {
                var (tag, _, val) = ReadEk();
                fields.Add(new AntiField { Tag = tag, Raw = val });
            }

            if (PeekTag() == 7)
            {
                pos++; // ek(7)
                int hrefLen = (int)ParseVarint(payload, ref pos);
                var href = Slice(payload, ref pos, hrefLen);
                int portLen = (int)ParseVarint(payload, ref pos);
                var port = portLen > 0 ? Slice(payload, ref pos, portLen) : Array.Empty<byte>();
                var c = Slice(payload, ref pos, 4);
                fields.Add(new AntiField { Tag = 7, Href = Latin1(href), Port = Latin1(port), C = c });
            }
            if (PeekTag() == 8) { pos++; fields.Add(new AntiField { Tag = 8, Va = { ParseVarint(payload, ref pos), ParseVarint(payload, ref pos) } }); }
            if (PeekTag() == 9) { var (_, _, v) = ReadEk(); fields.Add(new AntiField { Tag = 9, Str = Latin1(v) }); }
            if (PeekTag() == 10) { pos++; fields.Add(new AntiField { Tag = 10, Va = { ParseVarint(payload, ref pos) } }); }
            if (PeekTag() == 11) { pos++; fields.Add(new AntiField { Tag = 11, Pbc = Slice(payload, ref pos, 4) }); }
            foreach (int tg in new[] { 12, 13 })
                if (PeekTag() == tg) { var (_, _, v) = ReadEk(); fields.Add(new AntiField { Tag = tg, Str = Latin1(v) }); }
            if (PeekTag() == 14) { var (_, _, v) = ReadEk(); fields.Add(new AntiField { Tag = 14, Num = BigEndian(v) }); }
            if (PeekTag() == 15) { var (_, _, v) = ReadEk(); fields.Add(new AntiField { Tag = 15, Str = Latin1(v) }); }
            while (PeekTag() == 16 || PeekTag() == 17) { var (tag, _, v) = ReadEk(); fields.Add(new AntiField { Tag = tag, Str = Latin1(v) }); }
            foreach (int tg in new[] { 18, 19, 20 })
                if (PeekTag() == tg) { var (_, _, v) = ReadEk(); fields.Add(new AntiField { Tag = tg, Str = Latin1(v) }); }
            if (PeekTag() == 21) { var (_, _, v) = ReadEk(); fields.Add(new AntiField { Tag = 21, Num = BigEndian(v) }); }
            if (PeekTag() == 22) { var (_, _, v) = ReadEk(); fields.Add(new AntiField { Tag = 22, Num = BigEndian(v) }); }
            if (PeekTag() == 23) { var (_, _, v) = ReadEk(); fields.Add(new AntiField { Tag = 23, Str = Latin1(v) }); }
            foreach (int tg in new[] { 26, 27 })
                if (PeekTag() == tg) { pos++; fields.Add(new AntiField { Tag = tg, Va = { ParseVarint(payload, ref pos) } }); }
            if (PeekTag() == 28) { pos++; fields.Add(new AntiField { Tag = 28, Va = { ParseVarint(payload, ref pos), ParseVarint(payload, ref pos) } }); }

            rest = new byte[payload.Length - pos];
            Array.Copy(payload, pos, rest, 0, rest.Length);
            return fields;
        }

        // ======================= 自定义 base64 + 盐 =======================
        public static (byte[] raw, int m) CustomB64Decode(string enc)
        {
            int m = Idx[enc[^1]];
            int bitBuf = 0, bitCnt = 0;
            var outB = new List<byte>();
            for (int i = 0; i < enc.Length - 1; i++)
            {
                int idx = Idx[enc[i]];
                int v = idx < m ? idx : (idx == m ? 63 : idx - 1);
                bitBuf = (bitBuf << 6) | v; bitCnt += 6;
                if (bitCnt >= 8) { bitCnt -= 8; outB.Add((byte)((bitBuf >> bitCnt) & 0xff)); }
            }
            return (outB.ToArray(), m);
        }

        public static string CustomB64Encode(byte[] data, int m)
        {
            var sb = new StringBuilder();
            int bitBuf = 0, bitCnt = 0;
            foreach (byte b in data)
            {
                bitBuf = (bitBuf << 8) | b; bitCnt += 8;
                while (bitCnt >= 6) { bitCnt -= 6; sb.Append(MapEnc((bitBuf >> bitCnt) & 0x3f, m)); }
            }
            if (bitCnt > 0) sb.Append(MapEnc((bitBuf << (6 - bitCnt)) & 0x3f, m));
            sb.Append(Alphabet[m]);
            return sb.ToString();
        }

        private static char MapEnc(int v, int m)
        {
            int idx = v == 63 ? m : (v >= m ? v + 1 : v);
            return Alphabet[idx];
        }

        // ======================= deflate / inflate =======================
        public static byte[] Deflate(byte[] data)
        {
            using var outMs = new MemoryStream();
            using (var z = new ZLibStream(outMs, CompressionLevel.Optimal, leaveOpen: true))
                z.Write(data, 0, data.Length);
            return outMs.ToArray();
        }

        public static byte[] Inflate(byte[] zlibData)
        {
            using var ms = new MemoryStream(zlibData);
            using var z = new ZLibStream(ms, CompressionMode.Decompress);
            using var outMs = new MemoryStream();
            z.CopyTo(outMs);
            return outMs.ToArray();
        }

        // ======================= 顶层 Decode / Encode =======================
        public static AntiDecoded DecodeToken(string token)
        {
            token = token.Trim();
            if (!token.StartsWith(Prefix)) throw new ArgumentException($"token 不以 {Prefix} 开头");
            var (raw, m) = CustomB64Decode(token.Substring(Prefix.Length));
            // f 尾部恒 4 字节
            int fLen = FTail.Length;
            var deflateStream = new byte[raw.Length - fLen];
            var f = new byte[fLen];
            Array.Copy(raw, 0, deflateStream, 0, deflateStream.Length);
            Array.Copy(raw, raw.Length - fLen, f, 0, fLen);
            var inflated = Inflate(deflateStream);
            var payload = new byte[inflated.Length - 6];
            Array.Copy(inflated, 6, payload, 0, payload.Length);
            var fields = ParseFields(payload, out _);
            return new AntiDecoded { SaltM = m, Inflated = inflated, FTailBytes = f, Payload = payload, Fields = fields };
        }

        /// <summary>framed payload → token (deflate + f + 自定义base64+盐)。salt=null 用随机盐。</summary>
        public static string EncodeToken(byte[] framedPayload, byte[]? fTail = null, int? salt = null)
        {
            fTail ??= FTail;
            var raw = Concat(Deflate(framedPayload), fTail);
            int m = salt ?? Random.Shared.Next(0, 64);
            return Prefix + CustomB64Encode(raw, m);
        }

        /// <summary>字段列表 → 完整 token。</summary>
        public static string Encode(IEnumerable<AntiField> fields, byte[]? fTail = null, int? salt = null)
            => EncodeToken(Frame(PackFields(fields)), fTail, salt);

        /// <summary>解码一个 token 再纯代码重编码 (payload 字节一致, 仅盐/deflate 不同)。用于验证或换盐。</summary>
        public static string ReEncode(string token, int? salt = null)
        {
            var d = DecodeToken(token);
            return EncodeToken(Frame(PackFields(d.Fields)), d.FTailBytes, salt);
        }

        /// <summary>
        /// 以真机 token 为模板铸造新 token: 刷新动态字段 (tag22 时间戳ms / tag9 id 秒时间戳), 保留其余真机持久值。
        /// nowMs=null 用当前时间。<paramref name="pddUserId"/> 非空则覆盖 tag19 pdd_user_id (使与请求 pdduid 自洽)。
        /// 返回新 token。
        /// </summary>
        /// <summary>nano_fp 生成器字母表 (react_anti_co 随机模块, 64 字符)。</summary>
        public const string NanoFpAlphabet = "_~varfunctio0125634789bdegjhklmpqswxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        /// <summary>
        /// 生成一个 nano_fp (= tag16 nano_cookie_fp = tag17 nano_storage_fp)。
        /// 结构 (实测真机/jsdom 40字符, 逐位分析坐实): `XpmJn0`(6 固定 marker) + 12 随机(排除 _ ~) + `_`(pos18 分隔符) + 21 随机(全字母表)。
        ///   pos18 恒为 `_` (4/4 样本, 非巧合) 是服务端校验的结构关键; 前18位无 `_`; 尾21位 = 生成器 d(21) 自由随机。
        /// 客户端持久随机 ID (存 cookie+localStorage); 服务端校验其结构合法性(非日志历史/非env交叉), jsdom产的合法fp未上报也被接受。
        /// </summary>
        public static string GenNanoFp()
        {
            // 前缀 12 位: 排除 '_'(idx0) 和 '~'(idx1), 保证 pos18 的 '_' 是首个下划线(分隔符语义)
            var sb = new StringBuilder("XpmJn0");
            for (int i = 0; i < 12; i++) sb.Append(NanoFpAlphabet[2 + Random.Shared.Next(NanoFpAlphabet.Length - 2)]);
            sb.Append('_');   // pos18 分隔符
            for (int i = 0; i < 21; i++) sb.Append(NanoFpAlphabet[Random.Shared.Next(NanoFpAlphabet.Length)]);
            return sb.ToString();  // 6+12+1+21 = 40
        }

        public static string MintFromReal(string realToken, long? nowMs = null, string? pddUserId = null,
            string? ua = null, int? screenAvailW = null, int? screenAvailH = null, string? apiUid = null,
            string? pddVds = null, string? nanoFp = null, int? salt = null)
        {
            var d = DecodeToken(realToken);
            long ms = nowMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long sec = ms / 1000;
            foreach (var f in d.Fields)
            {
                if (f.Tag == 22) f.Num = ms;                       // 时间戳(ms)
                else if (f.Tag == 9 && f.Str != null)              // 随机id 第二段 = 秒时间戳
                {
                    int dash = f.Str.IndexOf('-');
                    string head = dash >= 0 ? f.Str.Substring(0, dash) : f.Str;
                    f.Str = head + "-" + sec;
                }
                else if (f.Tag == 19 && !string.IsNullOrEmpty(pddUserId))
                    f.Str = pddUserId;                             // pdd_user_id → 会话 uid
                else if (f.Tag == 15 && !string.IsNullOrEmpty(ua))
                    f.Str = ua;                                    // userAgent → 当前设备 (== 请求头 UA)
                else if (f.Tag == 20 && !string.IsNullOrEmpty(apiUid))
                    f.Str = apiUid;                                // api_uid (m.pinduoduo.net cookie) → 会话自身值
                else if (f.Tag == 23 && !string.IsNullOrEmpty(pddVds))
                    f.Str = pddVds;                                // pdd_vds (m.pinduoduo.net cookie) → 会话自身值
                else if ((f.Tag == 16 || f.Tag == 17) && !string.IsNullOrEmpty(nanoFp))
                    f.Str = nanoFp;                                // nano_cookie_fp / nano_storage_fp (同值) → 设备自身持久随机 fp
                else if (f.Tag == 8 && screenAvailW.HasValue && screenAvailH.HasValue && f.Va.Count >= 2)
                {
                    f.Va[0] = screenAvailW.Value;                  // 屏幕 availWidth/availHeight (CSS 逻辑像素)
                    f.Va[1] = screenAvailH.Value;
                }
            }
            return EncodeToken(Frame(PackFields(d.Fields)), d.FTailBytes, salt);
        }

        // ======================= helpers =======================
        private static byte[] Concat(params byte[][] arrs)
        {
            int n = 0; foreach (var a in arrs) n += a.Length;
            var r = new byte[n]; int o = 0;
            foreach (var a in arrs) { Array.Copy(a, 0, r, o, a.Length); o += a.Length; }
            return r;
        }
        private static byte[] Slice(byte[] d, ref int pos, int n)
        {
            var r = new byte[n]; Array.Copy(d, pos, r, 0, n); pos += n; return r;
        }
        private static string Latin1(byte[] b) => Encoding.Latin1.GetString(b);
        private static long BigEndian(byte[] b) { long v = 0; foreach (var x in b) v = (v << 8) | x; return v; }
        private static string ToHex(byte[]? b) => b == null ? "" : Convert.ToHexString(b).ToLowerInvariant();
    }
}
