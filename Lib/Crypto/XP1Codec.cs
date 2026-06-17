using System;
using System.Security.Cryptography;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// PDD x-p1 header 生成实现 (SecureNative.sdr, data_type=20 分支)
    ///
    /// 整体公式:
    ///   x-p1 = Base64( "040101" + p47 + RC4变体( payload, key = MD5(p47) ) )
    ///
    /// payload (78 字节, '&' 分隔):
    ///   seg1 & st & seg3 & ts2 & seg5
    ///
    /// 中间串 S58:
    ///   S58 = MD5(ul)[:16] & MD5(bd)[16:] & ac & ck & et & st   (ac/ck 通常为空)
    ///
    /// 各 segment:
    ///   seg1 = MD5_IV-B( MD5_IV-A( S58 ) )    — 双跳"魔改初始 IV"的标准 MD5
    ///   st   = 入参 (请求发起毫秒时间戳)
    ///   seg3 = lrand48() % 1817 + 0x4000      — 4 hex (伪随机)
    ///   ts2  = 当前毫秒时间戳                   — 13 位 (gettimeofday)
    ///   seg5 = S58 按 '&' 分 6 段, 每段从 0x11 起逐字符 XOR -> 6 字节 hex
    ///
    /// 魔改 IV (= AES 逆 S-box 逐字节代换硬编码常量):
    ///   IV-A 原像 = 33552201 52C1A689 98B11CF1 10432478
    ///   IV-B 原像 = 22452301 44C1A185 98B2DCF1 10328876
    ///
    /// RC4 变体: 标准 KSA, PRGA keystream 索引额外 +0x1A。
    ///
    /// 验证: 与 unidbg/抓包逐字节一致 (scripts/xp1_codec.py)。
    /// </summary>
    public static class XP1Codec
    {
        private const string Magic = "040101";
        private const byte XorInit = 0x11;
        private const int Seg3Mod = 1817;       // 0x719
        private const int Seg3Base = 0x4000;
        private const int Rc4KeystreamAdd = 0x1A;

        // IV 硬编码原像常量 (来自 libpdd_secure.so 反编译)
        private static readonly uint[] IvAConst = { 0x33552201, 0x52C1A689, 0x98B11CF1, 0x10432478 };
        private static readonly uint[] IvBConst = { 0x22452301, 0x44C1A185, 0x98B2DCF1, 0x10328876 };

        // 注意: IvA/IvB 依赖 AesInvSbox，必须在其之后初始化 → 用 Lazy 规避静态字段初始化顺序问题
        private static readonly Lazy<uint[]> _ivA = new(() => MakeIv(IvAConst));
        private static readonly Lazy<uint[]> _ivB = new(() => MakeIv(IvBConst));
        private static uint[] IvA => _ivA.Value;
        private static uint[] IvB => _ivB.Value;

        private static readonly Random Rng = new Random();

        // ==================== 顶层 API ====================

        /// <summary>
        /// 生成 x-p1 header。seg3/ts2 不传则自动用随机/当前时间。
        /// </summary>
        /// <param name="ul">入参 ul，如 "/video/config/fjbouedvm/dserubn"</param>
        /// <param name="bdJson">bd 字段 base64 解码后的 JSON 字符串</param>
        /// <param name="et">入参 et</param>
        /// <param name="st">入参 st (毫秒时间戳字符串)</param>
        /// <param name="p47">会话 UUID (36 字符)，同时是 x-p1 明文头与 RC4 key 来源</param>
        /// <param name="ac">ac 字段 (通常为空)</param>
        /// <param name="ck">ck 字段 (通常为空)</param>
        /// <param name="seg3">可选: 固定 seg3 (4 hex)，用于复现/测试</param>
        /// <param name="ts2">可选: 固定 ts2 (13 位毫秒)，用于复现/测试</param>
        public static string Generate(
            string ul, string bdJson, string et, string st, string p47,
            string ac = "", string ck = "", string? seg3 = null, string? ts2 = null)
        {
            string s58 = BuildS58(ul, bdJson, et, st, ac, ck);
            string seg1 = CalcSeg1(s58);
            string seg5 = CalcSeg5(s58);
            seg3 ??= CalcSeg3();
            ts2 ??= DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();

            string payload = $"{seg1}&{st}&{seg3}&{ts2}&{seg5}";

            byte[] key = Md5Std(Encoding.ASCII.GetBytes(p47));
            byte[] floating = Rc4Variant(key, Encoding.ASCII.GetBytes(payload));

            byte[] blob = Concat(Encoding.ASCII.GetBytes(Magic), Encoding.ASCII.GetBytes(p47), floating);
            return Convert.ToBase64String(blob);
        }

        // ==================== S58 / segments ====================

        /// <summary>S58 = MD5(ul)[:16] & MD5(bd)[16:] & ac & ck & et & st</summary>
        public static string BuildS58(string ul, string bdJson, string et, string st,
                                      string ac = "", string ck = "")
        {
            string a1 = Md5Hex(ul).Substring(0, 16);
            string a2 = Md5Hex(bdJson).Substring(16);
            return $"{a1}&{a2}&{ac}&{ck}&{et}&{st}";
        }

        /// <summary>seg1 = MD5_IV-B( MD5_IV-A(S58) )，双跳魔改 IV-MD5</summary>
        public static string CalcSeg1(string s58)
        {
            byte[] h1 = Md5WithIv(Encoding.ASCII.GetBytes(s58), IvA);
            byte[] seg1 = Md5WithIv(h1, IvB);
            return ToHex(seg1);
        }

        /// <summary>seg5 = S58 按 '&' 分段, 每段从 0x11 起逐字符 XOR -> 6 字节 hex</summary>
        public static string CalcSeg5(string s58)
        {
            var sb = new StringBuilder();
            foreach (string part in s58.Split('&'))
            {
                byte acc = XorInit;
                foreach (char ch in part)
                    acc ^= (byte)ch;
                sb.Append(acc.ToString("x2"));
            }
            return sb.ToString();
        }

        /// <summary>seg3 = lrand48() % 1817 + 0x4000 (4 hex)。离线生成用普通随机即可。</summary>
        public static string CalcSeg3()
        {
            int v = Rng.Next(0, int.MaxValue) % Seg3Mod + Seg3Base;
            return v.ToString("x4");
        }

        // ==================== 魔改 IV ====================

        /// <summary>对每个 u32 常量做 AES 逆 S-box 逐字节代换，得到 4 字 IV</summary>
        private static uint[] MakeIv(uint[] consts)
        {
            var iv = new uint[4];
            for (int i = 0; i < 4; i++)
                iv[i] = InvSboxWord(consts[i]);
            return iv;
        }

        /// <summary>对 u32 的 4 字节分别查 AES 逆 S-box (保持字节序)</summary>
        public static uint InvSboxWord(uint c)
        {
            byte b0 = AesInvSbox[c & 0xFF];
            byte b1 = AesInvSbox[(c >> 8) & 0xFF];
            byte b2 = AesInvSbox[(c >> 16) & 0xFF];
            byte b3 = AesInvSbox[(c >> 24) & 0xFF];
            return (uint)(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24));
        }

        // ==================== MD5 (可指定初始 IV) ====================

        private static readonly uint[] MdK = BuildMdK();
        private static readonly int[] MdS =
        {
            7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
            5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
            4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
            6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
        };

        private static uint[] BuildMdK()
        {
            var k = new uint[64];
            for (int i = 0; i < 64; i++)
                k[i] = (uint)(long)(Math.Abs(Math.Sin(i + 1)) * 4294967296.0);
            return k;
        }

        /// <summary>标准 MD5 压缩，但初始 IV 可指定 (iv = a,b,c,d 四个 u32)。返回 16 字节摘要。</summary>
        public static byte[] Md5WithIv(byte[] msg, uint[] iv)
        {
            uint a0 = iv[0], b0 = iv[1], c0 = iv[2], d0 = iv[3];

            long origBits = (long)msg.Length * 8;
            int padLen = msg.Length + 1;
            while (padLen % 64 != 56) padLen++;
            byte[] buf = new byte[padLen + 8];
            Array.Copy(msg, buf, msg.Length);
            buf[msg.Length] = 0x80;
            for (int i = 0; i < 8; i++)
                buf[padLen + i] = (byte)(origBits >> (8 * i));

            for (int off = 0; off < buf.Length; off += 64)
            {
                uint[] m = new uint[16];
                for (int i = 0; i < 16; i++)
                    m[i] = (uint)(buf[off + i * 4]
                                | (buf[off + i * 4 + 1] << 8)
                                | (buf[off + i * 4 + 2] << 16)
                                | (buf[off + i * 4 + 3] << 24));

                uint A = a0, B = b0, C = c0, D = d0;
                for (int i = 0; i < 64; i++)
                {
                    uint f; int g;
                    if (i < 16)      { f = (B & C) | (~B & D);          g = i; }
                    else if (i < 32) { f = (D & B) | (~D & C);          g = (5 * i + 1) % 16; }
                    else if (i < 48) { f = B ^ C ^ D;                   g = (3 * i + 5) % 16; }
                    else             { f = C ^ (B | ~D);                g = (7 * i) % 16; }

                    f = unchecked(f + A + MdK[i] + m[g]);
                    A = D; D = C; C = B;
                    B = unchecked(B + Rotl(f, MdS[i]));
                }
                a0 = unchecked(a0 + A); b0 = unchecked(b0 + B);
                c0 = unchecked(c0 + C); d0 = unchecked(d0 + D);
            }

            byte[] outp = new byte[16];
            WriteLE32(outp, 0, a0); WriteLE32(outp, 4, b0);
            WriteLE32(outp, 8, c0); WriteLE32(outp, 12, d0);
            return outp;
        }

        private static byte[] Md5Std(byte[] data)
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(data);
        }

        private static string Md5Hex(string s) => ToHex(Md5Std(Encoding.UTF8.GetBytes(s)));

        // ==================== RC4 变体 ====================

        /// <summary>标准 KSA + PRGA，keystream 取值索引额外 +add (PDD 用 0x1A)</summary>
        public static byte[] Rc4Variant(byte[] key, byte[] data, int add = Rc4KeystreamAdd)
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
                byte k = s[(s[x] + s[y] + add) & 0xFF];
                outp[n] = (byte)(data[n] ^ k);
            }
            return outp;
        }

        // ==================== 辅助方法 ====================

        private static uint Rotl(uint x, int c) => (x << c) | (x >> (32 - c));

        private static void WriteLE32(byte[] buf, int offset, uint val)
        {
            buf[offset]     = (byte)(val);
            buf[offset + 1] = (byte)(val >> 8);
            buf[offset + 2] = (byte)(val >> 16);
            buf[offset + 3] = (byte)(val >> 24);
        }

        private static string ToHex(byte[] b)
        {
            var sb = new StringBuilder(b.Length * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2"));
            return sb.ToString();
        }

        private static byte[] Concat(params byte[][] arrays)
        {
            int total = 0;
            foreach (var a in arrays) total += a.Length;
            byte[] r = new byte[total];
            int pos = 0;
            foreach (var a in arrays) { Array.Copy(a, 0, r, pos, a.Length); pos += a.Length; }
            return r;
        }

        // AES 逆 S-box (标准)
        private static readonly byte[] AesInvSbox =
        {
            0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
            0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
            0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
            0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
            0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
            0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
            0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
            0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
            0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
            0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
            0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
            0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
            0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
            0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
            0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
            0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
        };
    }
}
