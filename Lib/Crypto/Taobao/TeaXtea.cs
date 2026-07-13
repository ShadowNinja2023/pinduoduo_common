using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib.Crypto.Taobao
{
    internal static class TeaXtea
    {

        private const uint M32 = 0xFFFFFFFF;

        internal static byte[] SubArray(byte[] data, int offset, int length = -1)
        {
            if (length < 0) length = data.Length - offset;
            var result = new byte[length];
            Buffer.BlockCopy(data, offset, result, 0, length);
            return result;
        }

        /// <summary>已确认的 TEA 加密 detect_id_policy_id 集合</summary>
        public static readonly HashSet<string> TeaEncKeys = new HashSet<string>
        {
            "711d_7326", "3c52_3736", "146f_e78e", "13d7_bbe0", "a3ea_7326",
            "71bb_b1b2", "80b8_b151", "146f_b151", "2f06_3736", "9bbc_3736",
            "33f7_bbe0"
        };

        /// <summary>bb98 交叉引用映射: bb98加密项 → bbe0 key 项</summary>
        public static readonly Dictionary<string, string> Bb98CrossTea = new Dictionary<string, string>
        {
            { "1071_bb98", "c477_bbe0" },
            { "c3cf_bb98", "9943_bbe0" },
            { "99bd_bb98", "7c57_bbe0" }
        };

        public const string Bb98DeltaKey = "9e2a_bb98";
        public const string E0a1B1b2Key = "e0a1_b1b2";
        public const string E0a1DeltaSrc = "920a_b1b2";

        // 71bb 校验的两个目标检测项
        public const string Key71bb = "71bb_b1b2";
        public const string Key71bbTargetA = "3cea_b078"; // gid_A=0x23
        public const string Key71bbTargetB = "9943_bbe0"; // gid_B=0x12
        public const string KeyD0d1 = "d0d1_b1b2";       // 71bb TEA delta 来源

        // ═══════════════════════════════════════════════════════════
        // 1. 标准 TEA/XTEA 交替解密 (TEA_ENC_KEYS 集合)
        // ═══════════════════════════════════════════════════════════

        /// <summary>
        /// 二次 TEA/XTEA 交替解密
        /// 密文格式: base64 → [2B delta_hi] + [data] + [2B delta_lo]
        /// </summary>
        public static byte[] TeaXteaDecrypt(byte[] payloadB64, string detectId, string policyId)
        {
            var clean = TrimTrailingZeros(payloadB64);
            var raw = Base64DecodeWithPadding(clean);
            if (raw == null || raw.Length < 8) return null;

            uint delta = (uint)((raw[0] << 24) | (raw[1] << 16) | (raw[raw.Length - 2] << 8) | raw[raw.Length - 1]);
            int rounds = (int)(delta % 10) + 10;
            var data = SubArray(raw, 2, raw.Length - 4);
            if (data.Length < 8 || data.Length % 8 != 0) return null;

            uint sumOffset = 0;
            try { sumOffset = Convert.ToUInt32(policyId, 16); } catch { }

            var k4 = new uint[4];
            var ascii = Encoding.ASCII.GetBytes(detectId.Substring(0, Math.Min(4, detectId.Length)));
            for (int i = 0; i < 4 && i < ascii.Length; i++) k4[i] = ascii[i];

            uint sumInit = (uint)((long)delta * rounds & M32) + sumOffset;
            var ret = new byte[data.Length];

            for (int j = 0; j < data.Length; j += 8)
            {
                int blockIdx = j / 8;
                uint w0 = ReadU32BE(data, j);
                uint w1 = ReadU32BE(data, j + 4);

                if (blockIdx % 2 == 0)
                {
                    // TEA 解密
                    uint s = sumInit;
                    for (int r = 0; r < rounds; r++)
                    {
                        w1 = (uint)(w1 - ((((w0 << 4) + k4[2]) ^ (w0 + s) ^ ((w0 >> 5) + k4[3])) & M32));
                        w0 = (uint)(w0 - ((((w1 << 4) + k4[0]) ^ (w1 + s) ^ ((w1 >> 5) + k4[1])) & M32));
                        s = (uint)(s - delta);
                    }
                }
                else
                {
                    // XTEA 解密
                    uint x = sumInit;
                    for (int r = 0; r < rounds; r++)
                    {
                        w1 = (uint)(w1 - ((((w0 << 4) ^ (w0 >> 5)) + w0) ^ (x + k4[(x >> 11) & 3])));
                        x = (uint)(x - delta);
                        w0 = (uint)(w0 - ((((w1 << 4) ^ (w1 >> 5)) + w1) ^ (x + k4[x & 3])));
                    }
                }
                WriteU32BE(ret, j, w0);
                WriteU32BE(ret, j + 4, w1);
            }
            return TrimTrailingZeros(ret);
        }

        // ═══════════════════════════════════════════════════════════
        // 2. bb98 交叉引用 TEA 解密
        // ═══════════════════════════════════════════════════════════

        /// <summary>bb98 交叉引用 TEA/XTEA 解密, rounds=13</summary>
        public static byte[] Bb98CrossTeaDecrypt(byte[] payloadB64, string keyDidPid, uint delta)
        {
            var clean = TrimTrailingZeros(payloadB64);
            var raw = Base64DecodeWithPadding(clean);
            if (raw == null || raw.Length < 8 || raw.Length % 8 != 0) return null;

            const int rounds = 13;
            var parts = keyDidPid.Split('_');
            var k4 = new uint[4];
            var ascii = Encoding.ASCII.GetBytes(parts[0].Substring(0, Math.Min(4, parts[0].Length)));
            for (int i = 0; i < 4 && i < ascii.Length; i++) k4[i] = ascii[i];

            uint sumOffset = 0;
            if (parts.Length > 1) try { sumOffset = Convert.ToUInt32(parts[1], 16); } catch { }
            uint sumInit = (uint)((long)delta * rounds & M32) + sumOffset;

            var ret = new byte[raw.Length];
            for (int j = 0; j < raw.Length; j += 8)
            {
                uint w0 = ReadU32BE(raw, j);
                uint w1 = ReadU32BE(raw, j + 4);
                if ((j / 8) % 2 == 0)
                {
                    uint s = sumInit;
                    for (int r = 0; r < rounds; r++)
                    {
                        w1 = (uint)(w1 - ((((w0 << 4) + k4[2]) ^ (w0 + s) ^ ((w0 >> 5) + k4[3])) & M32));
                        w0 = (uint)(w0 - ((((w1 << 4) + k4[0]) ^ (w1 + s) ^ ((w1 >> 5) + k4[1])) & M32));
                        s = (uint)(s - delta);
                    }
                }
                else
                {
                    uint x = sumInit;
                    for (int r = 0; r < rounds; r++)
                    {
                        w1 = (uint)(w1 - ((((w0 << 4) ^ (w0 >> 5)) + w0) ^ (x + k4[(x >> 11) & 3])));
                        x = (uint)(x - delta);
                        w0 = (uint)(w0 - ((((w1 << 4) ^ (w1 >> 5)) + w1) ^ (x + k4[x & 3])));
                    }
                }
                WriteU32BE(ret, j, w0);
                WriteU32BE(ret, j + 4, w1);
            }
            return TrimTrailingZeros(ret);
        }

        // ═══════════════════════════════════════════════════════════
        // 3. e0a1_b1b2 TEA/XTEA 变体解密
        // ═══════════════════════════════════════════════════════════

        /// <summary>
        /// e0a1_b1b2 TEA/XTEA 变体解密
        /// 差异: sum_init 不含 delta*rounds; 偶数块 sum 先递增; 密文 swap(v0,v1)
        /// </summary>
        public static byte[] E0a1TeaXteaDecrypt(byte[] payloadB64, string detectId, string policyId, uint delta)
        {
            var clean = TrimTrailingZeros(payloadB64);
            var raw = Base64DecodeWithPadding(clean);
            if (raw == null || raw.Length < 8) return null;

            const int rounds = 12;
            uint sumInit = 0;
            try { sumInit = Convert.ToUInt32(policyId, 16); } catch { }

            var k = new uint[4];
            for (int i = 0; i < 4 && i < detectId.Length; i++)
                k[i] = (uint)detectId[i];

            var ret = new byte[raw.Length];
            for (int j = 0; j < raw.Length; j += 8)
            {
                if (j + 8 > raw.Length)
                {
                    Buffer.BlockCopy(raw, j, ret, j, raw.Length - j);
                    continue;
                }
                // 密文存储 swap: (v1, v0)
                uint v1 = ReadU32BE(raw, j);
                uint v0 = ReadU32BE(raw, j + 4);
                int bi = j / 8;

                if (bi % 2 == 0)
                {
                    // 偶数块 TEA: sum 先递增
                    uint s = (uint)(sumInit + (long)delta * rounds);
                    for (int r = 0; r < rounds; r++)
                    {
                        v0 = (uint)(v0 - ((((v1 << 4) + k[2]) ^ (v1 + s) ^ ((v1 >> 5) + k[3])) & M32));
                        v1 = (uint)(v1 - ((((v0 << 4) + k[0]) ^ (v0 + s) ^ ((v0 >> 5) + k[1])) & M32));
                        s = (uint)(s - delta);
                    }
                }
                else
                {
                    // 奇数块 XTEA: sum 在中间递增
                    uint s = (uint)(sumInit + (long)delta * rounds);
                    for (int r = 0; r < rounds; r++)
                    {
                        v0 = (uint)(v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[(s >> 11) & 3])));
                        s = (uint)(s - delta);
                        v1 = (uint)(v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[s & 3])));
                    }
                }
                // 输出也 swap 回来
                WriteU32BE(ret, j, v1);
                WriteU32BE(ret, j + 4, v0);
            }
            return ret;
        }

        // ═══════════════════════════════════════════════════════════
        // 4. 内嵌 es (et.pl.es) TEA/XTEA 解密 (FUCK key)
        // ═══════════════════════════════════════════════════════════

        private static readonly uint[] EmbeddedKey = { 0x4655434b, 0x55434b46, 0x434b4655, 0x4b465543 };
        private const uint EmbeddedDelta = 0x4655434b;
        private const uint EmbeddedSumInit = 0x52;
        private const int EmbeddedRounds = 12;

        /// <summary>内嵌 es 解密: TEA/XTEA 交替, FUCK key</summary>
        public static byte[] DecryptEmbeddedEs(byte[] ciphertext)
        {
            int numBlocks = ciphertext.Length / 8;
            var pt = new byte[numBlocks * 8];

            for (int i = 0; i < numBlocks; i++)
            {
                int off = i * 8;
                uint v0 = ReadU32BE(ciphertext, off);
                uint v1 = ReadU32BE(ciphertext, off + 4);

                if (i % 2 == 0)
                {
                    // 偶数块: 标准 TEA
                    uint s = unchecked((uint)(EmbeddedSumInit + (long)EmbeddedDelta * EmbeddedRounds));
                    for (int r = 0; r < EmbeddedRounds; r++)
                    {
                        v1 = (uint)(v1 - ((((v0 << 4) + EmbeddedKey[2]) ^ (v0 + s) ^ ((v0 >> 5) + EmbeddedKey[3])) & M32));
                        v0 = (uint)(v0 - ((((v1 << 4) + EmbeddedKey[0]) ^ (v1 + s) ^ ((v1 >> 5) + EmbeddedKey[1])) & M32));
                        s = (uint)(s - EmbeddedDelta);
                    }
                }
                else
                {
                    // 奇数块: XTEA 变体 (v55)
                    uint sum2 = unchecked((uint)(-(int)EmbeddedDelta));
                    uint s = unchecked((uint)(EmbeddedSumInit + (long)EmbeddedDelta * EmbeddedRounds));
                    for (int r = 0; r < EmbeddedRounds; r++)
                    {
                        uint idx1 = (s >> 11) & 3;
                        v1 = (uint)(v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + EmbeddedKey[idx1])));
                        uint sps = (uint)(sum2 + s);
                        uint idx2 = sps & 3;
                        s = (uint)(s - EmbeddedDelta);
                        v0 = (uint)(v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sps + EmbeddedKey[idx2])));
                    }
                }
                WriteU32BE(pt, off, v0);
                WriteU32BE(pt, off + 4, v1);
            }
            // 去尾部零填充
            int end = pt.Length;
            while (end > 0 && pt[end - 1] == 0) end--;
            return SubArray(pt, 0, end);
        }

        // ═══════════════════════════════════════════════════════════
        // 5. 正向加密方法 (解密的逆过程)
        // ═══════════════════════════════════════════════════════════

        /// <summary>
        /// 标准 TEA/XTEA 交替加密 (TeaXteaDecrypt 的逆)
        /// 输出格式: base64([2B delta_hi] + [encrypted_data] + [2B delta_lo])
        /// </summary>
        public static byte[] TeaXteaEncrypt(byte[] plaintext, string detectId, string policyId, uint? forceDelta = null)
        {
            // 填充到 8 字节对齐
            int padLen = (plaintext.Length + 7) / 8 * 8;
            var data = new byte[padLen];
            Buffer.BlockCopy(plaintext, 0, data, 0, plaintext.Length);

            // 生成或使用指定的 delta
            uint delta = forceDelta ?? GenerateDelta();
            int rounds = (int)(delta % 10) + 10;

            uint sumOffset = 0;
            try { sumOffset = Convert.ToUInt32(policyId, 16); } catch { }

            var k4 = new uint[4];
            var ascii = Encoding.ASCII.GetBytes(detectId.Substring(0, Math.Min(4, detectId.Length)));
            for (int i = 0; i < 4 && i < ascii.Length; i++) k4[i] = ascii[i];

            uint sumInit = (uint)((long)delta * rounds & M32) + sumOffset;
            var enc = new byte[data.Length];

            for (int j = 0; j < data.Length; j += 8)
            {
                int blockIdx = j / 8;
                uint w0 = ReadU32BE(data, j);
                uint w1 = ReadU32BE(data, j + 4);

                if (blockIdx % 2 == 0)
                {
                    // TEA 加密 (解密的逆序)
                    uint s = sumOffset; // sum 从 sumOffset 开始递增
                    for (int r = 0; r < rounds; r++)
                    {
                        s = (uint)(s + delta);
                        w0 = (uint)(w0 + ((((w1 << 4) + k4[0]) ^ (w1 + s) ^ ((w1 >> 5) + k4[1])) & M32));
                        w1 = (uint)(w1 + ((((w0 << 4) + k4[2]) ^ (w0 + s) ^ ((w0 >> 5) + k4[3])) & M32));
                    }
                }
                else
                {
                    // XTEA 加密
                    uint x = sumOffset;
                    for (int r = 0; r < rounds; r++)
                    {
                        w0 = (uint)(w0 + ((((w1 << 4) ^ (w1 >> 5)) + w1) ^ (x + k4[x & 3])));
                        x = (uint)(x + delta);
                        w1 = (uint)(w1 + ((((w0 << 4) ^ (w0 >> 5)) + w0) ^ (x + k4[(x >> 11) & 3])));
                    }
                }
                WriteU32BE(enc, j, w0);
                WriteU32BE(enc, j + 4, w1);
            }

            // 输出格式: [2B delta_hi] + [encrypted_data] + [2B delta_lo]
            var raw = new byte[2 + enc.Length + 2];
            raw[0] = (byte)(delta >> 24);
            raw[1] = (byte)(delta >> 16);
            Buffer.BlockCopy(enc, 0, raw, 2, enc.Length);
            raw[raw.Length - 2] = (byte)(delta >> 8);
            raw[raw.Length - 1] = (byte)(delta);

            return Encoding.GetEncoding("latin1").GetBytes(Convert.ToBase64String(raw));
        }

        /// <summary>
        /// bb98 交叉引用 TEA/XTEA 加密 (Bb98CrossTeaDecrypt 的逆)
        /// </summary>
        public static byte[] Bb98CrossTeaEncrypt(byte[] plaintext, string keyDidPid, uint delta)
        {
            int padLen = (plaintext.Length + 7) / 8 * 8;
            var data = new byte[padLen];
            Buffer.BlockCopy(plaintext, 0, data, 0, plaintext.Length);

            const int rounds = 13;
            var parts = keyDidPid.Split('_');
            var k4 = new uint[4];
            var ascii = Encoding.ASCII.GetBytes(parts[0].Substring(0, Math.Min(4, parts[0].Length)));
            for (int i = 0; i < 4 && i < ascii.Length; i++) k4[i] = ascii[i];

            uint sumOffset = 0;
            if (parts.Length > 1) try { sumOffset = Convert.ToUInt32(parts[1], 16); } catch { }

            var enc = new byte[data.Length];
            for (int j = 0; j < data.Length; j += 8)
            {
                uint w0 = ReadU32BE(data, j);
                uint w1 = ReadU32BE(data, j + 4);
                if ((j / 8) % 2 == 0)
                {
                    uint s = sumOffset;
                    for (int r = 0; r < rounds; r++)
                    {
                        s = (uint)(s + delta);
                        w0 = (uint)(w0 + ((((w1 << 4) + k4[0]) ^ (w1 + s) ^ ((w1 >> 5) + k4[1])) & M32));
                        w1 = (uint)(w1 + ((((w0 << 4) + k4[2]) ^ (w0 + s) ^ ((w0 >> 5) + k4[3])) & M32));
                    }
                }
                else
                {
                    uint x = sumOffset;
                    for (int r = 0; r < rounds; r++)
                    {
                        w0 = (uint)(w0 + ((((w1 << 4) ^ (w1 >> 5)) + w1) ^ (x + k4[x & 3])));
                        x = (uint)(x + delta);
                        w1 = (uint)(w1 + ((((w0 << 4) ^ (w0 >> 5)) + w0) ^ (x + k4[(x >> 11) & 3])));
                    }
                }
                WriteU32BE(enc, j, w0);
                WriteU32BE(enc, j + 4, w1);
            }

            return Encoding.GetEncoding("latin1").GetBytes(Convert.ToBase64String(enc));
        }

        /// <summary>
        /// e0a1_b1b2 TEA/XTEA 变体加密 (E0a1TeaXteaDecrypt 的逆)
        /// 差异: sum_init 不含 delta*rounds; 偶数块 sum 先递增; 密文 swap(v0,v1)
        /// 注意: 解密器输出时做了 swap 写回, 所以加密器输入也需要先 swap
        /// </summary>
        public static byte[] E0a1TeaXteaEncrypt(byte[] plaintext, string detectId, string policyId, uint delta)
        {
            int padLen = (plaintext.Length + 7) / 8 * 8;
            var data = new byte[padLen];
            Buffer.BlockCopy(plaintext, 0, data, 0, plaintext.Length);

            const int rounds = 12;
            uint sumInit = 0;
            try { sumInit = Convert.ToUInt32(policyId, 16); } catch { }

            var k = new uint[4];
            for (int i = 0; i < 4 && i < detectId.Length; i++)
                k[i] = (uint)detectId[i];

            var enc = new byte[data.Length];
            for (int j = 0; j < data.Length; j += 8)
            {
                if (j + 8 > data.Length)
                {
                    Buffer.BlockCopy(data, j, enc, j, data.Length - j);
                    continue;
                }
                // 解密器写回时做了 swap: ret[j]=v1, ret[j+4]=v0
                // 所以加密器输入也要 swap 读取, 使得解密器 swap 写回后恢复原始顺序
                uint v1 = ReadU32BE(data, j);
                uint v0 = ReadU32BE(data, j + 4);
                int bi = j / 8;

                if (bi % 2 == 0)
                {
                    // 偶数块 TEA: sum 先递增
                    uint s = sumInit;
                    for (int r = 0; r < rounds; r++)
                    {
                        s = (uint)(s + delta);
                        v1 = (uint)(v1 + ((((v0 << 4) + k[0]) ^ (v0 + s) ^ ((v0 >> 5) + k[1])) & M32));
                        v0 = (uint)(v0 + ((((v1 << 4) + k[2]) ^ (v1 + s) ^ ((v1 >> 5) + k[3])) & M32));
                    }
                }
                else
                {
                    // 奇数块 XTEA: sum 在中间递增
                    uint s = sumInit;
                    for (int r = 0; r < rounds; r++)
                    {
                        v1 = (uint)(v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (s + k[s & 3])));
                        s = (uint)(s + delta);
                        v0 = (uint)(v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (s + k[(s >> 11) & 3])));
                    }
                }
                // 密文存储 swap: (v1, v0)
                WriteU32BE(enc, j, v1);
                WriteU32BE(enc, j + 4, v0);
            }

            return Encoding.GetEncoding("latin1").GetBytes(Convert.ToBase64String(enc));
        }

        // ═══════════════════════════════════════════════════════════
        // 6. e0a1 校验表构建 (正向)
        // ═══════════════════════════════════════════════════════════

        /// <summary>gid → 摘要算法类型</summary>
        public enum DigestAlgo { XorPairHash, PairXorHash, FullSum, EvenSum, Crc16 }

        /// <summary>gid → (算法, K值) 映射</summary>
        public static readonly Dictionary<byte, (DigestAlgo algo, int K)> GidAlgoMap =
            new Dictionary<byte, (DigestAlgo, int)>
            {
                { 0x02, (DigestAlgo.EvenSum, 1) },
                { 0x07, (DigestAlgo.FullSum, 1) },
                { 0x08, (DigestAlgo.XorPairHash, 10) },
                { 0x0a, (DigestAlgo.FullSum, 10) },
                { 0x1e, (DigestAlgo.FullSum, 1) },
                { 0x1f, (DigestAlgo.XorPairHash, 10) },
                { 0x20, (DigestAlgo.EvenSum, 1) },
                { 0x21, (DigestAlgo.PairXorHash, 10) },
                { 0x22, (DigestAlgo.Crc16, 0) },  // CRC16 直接使用, K 无意义
                { 0x24, (DigestAlgo.XorPairHash, 10) },
            };

        /// <summary>gid → detect_id_policy_id 映射</summary>
        public static readonly Dictionary<byte, string> GidDetectIdMap =
            new Dictionary<byte, string>
            {
                { 0x02, "0174_cecf" },
                { 0x07, "ba2e_b078" },
                { 0x08, "ba2e_b078" },
                { 0x0a, "0ca5_613d" },
                { 0x1e, "bced_7c1c" },
                { 0x1f, "3ed1_cecf" },
                { 0x20, "db95_cecf" },
                { 0x21, "e1dc_cecf" },
                { 0x22, "71f3_b078" },
                { 0x24, "d79b_cecf" },
            };

        /// <summary>e0a1 自身的 gid</summary>
        public const byte E0a1SelfGid = 0x2e; // 46

        /// <summary>
        /// 计算单个检测项的摘要值
        /// value = (raw % 10) * K * raw &amp; 0xFFFF (CRC16 除外)
        /// </summary>
        public static ushort ComputeDigest(byte[] data, DigestAlgo algo, int K)
        {
            if (algo == DigestAlgo.Crc16)
                return Crc16(data);

            int raw;
            switch (algo)
            {
                case DigestAlgo.XorPairHash:
                    raw = XorPairHash(data);
                    break;
                case DigestAlgo.PairXorHash:
                    raw = PairXorHash(data);
                    break;
                case DigestAlgo.FullSum:
                    raw = FullSum(data);
                    break;
                case DigestAlgo.EvenSum:
                    raw = EvenSum(data);
                    break;
                default:
                    throw new ArgumentException($"未知算法: {algo}");
            }
            return (ushort)((raw % 10) * K * raw & 0xFFFF);
        }

        /// <summary>相邻字节 XOR: sum(data[i]^data[i+1]) + data[-1]</summary>
        public static int XorPairHash(byte[] data)
        {
            if (data.Length == 0) return 0;
            int h = 0;
            for (int i = 0; i < data.Length - 1; i++)
                h += data[i] ^ data[i + 1];
            h += data[data.Length - 1];
            return h;
        }

        /// <summary>成对字节 XOR: sum(data[2i+1]^data[2i])</summary>
        public static int PairXorHash(byte[] data)
        {
            int h = 0;
            for (int i = 0; i < data.Length - 1; i += 2)
                h += data[i + 1] ^ data[i];
            return h;
        }

        /// <summary>全字节求和</summary>
        public static int FullSum(byte[] data)
        {
            int h = 0;
            for (int i = 0; i < data.Length; i++) h += data[i];
            return h;
        }

        /// <summary>偶数索引位字节求和: data[0], data[2], data[4], ...</summary>
        public static int EvenSum(byte[] data)
        {
            int h = 0;
            for (int i = 0; i < data.Length; i += 2) h += data[i];
            return h;
        }

        /// <summary>CRC16: poly=0x8408, init=len(data)</summary>
        public static ushort Crc16(byte[] data)
        {
            ushort crc = (ushort)data.Length;
            for (int i = 0; i < data.Length; i++)
            {
                crc ^= data[i];
                for (int bit = 0; bit < 8; bit++)
                {
                    if ((crc & 1) != 0)
                        crc = (ushort)((crc >> 1) ^ 0x8408);
                    else
                        crc >>= 1;
                }
            }
            return crc;
        }

        /// <summary>
        /// 构建 e0a1 校验表明文
        /// 格式: [自身gid 1B] + 10 × [目标gid 1B, 摘要值u16 2B 大端序]
        /// </summary>
        /// <param name="detectItems">所有检测项 (detect_id_policy_id → 明文值)</param>
        /// <returns>31B 明文 (1 + 10*3)</returns>
        public static byte[] BuildE0a1Plaintext(Dictionary<string, string> detectItems)
        {
            // 排序的 gid 列表: 2, 7, 8, 10, 30, 31, 32, 33, 34, 36
            var sortedGids = new byte[] { 0x02, 0x07, 0x08, 0x0a, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x24 };

            var result = new byte[1 + sortedGids.Length * 3]; // 31B
            result[0] = E0a1SelfGid; // 首字节 = 自身 gid (0x2e)

            int pos = 1;
            for (int i = 0; i < sortedGids.Length; i++)
            {
                byte gid = sortedGids[i];
                result[pos] = gid;

                string didPid = GidDetectIdMap[gid];
                var (algo, K) = GidAlgoMap[gid];

                // 查找检测项的值
                string value = null;
                if (detectItems.TryGetValue(didPid, out var v))
                    value = v;

                // 值为空时使用 "NULL" 占位
                string input = string.IsNullOrEmpty(value) ? "NULL" : value;
                byte[] inputBytes = Encoding.GetEncoding("latin1").GetBytes(input);

                ushort digest = ComputeDigest(inputBytes, algo, K);
                // 大端序写入
                result[pos + 1] = (byte)(digest >> 8);
                result[pos + 2] = (byte)(digest & 0xFF);
                pos += 3;
            }
            return result;
        }

        /// <summary>
        /// 构建 71bb:b1b2 的 7 字节明文 (使用 CRC16 算法)
        /// 结构: [rand 1B] [gid_A=0x23] [CRC16_A 2B BE] [gid_B=0x12] [CRC16_B 2B BE]
        /// </summary>
        /// <param name="detectItems">检测项字典 (key="detectId_policyId")</param>
        /// <param name="rng">随机数生成器 (用于 rand 字节)</param>
        /// <returns>7 字节明文, 或 null (缺少目标检测项时)</returns>
        public static byte[] Build71bbPlaintext(Dictionary<string, string> detectItems, Random rng = null)
        {
            // 查找两个校验目标的值
            string valA = null, valB = null;
            detectItems.TryGetValue(Key71bbTargetA.Replace('_', ':'), out valA);
            detectItems.TryGetValue(Key71bbTargetB.Replace('_', ':'), out valB);

            if (string.IsNullOrEmpty(valA) || string.IsNullOrEmpty(valB))
                return null;

            byte[] dataA = Encoding.GetEncoding("latin1").GetBytes(valA);
            byte[] dataB = Encoding.GetEncoding("latin1").GetBytes(valB);

            ushort crcA = Crc16(dataA);
            ushort crcB = Crc16(dataB);

            if (rng == null) rng = new Random();
            byte rand = (byte)((rng.Next() % 99) + 1); // 1~99

            var plain = new byte[7];
            plain[0] = rand;
            plain[1] = 0x23; // gid_A
            plain[2] = (byte)(crcA >> 8);   // 大端序
            plain[3] = (byte)(crcA & 0xFF);
            plain[4] = 0x12; // gid_B
            plain[5] = (byte)(crcB >> 8);
            plain[6] = (byte)(crcB & 0xFF);
            return plain;
        }

        /// <summary>生成随机 delta (用于标准 TEA 加密)</summary>
        private static uint GenerateDelta()
        {
            var rng = new Random();
            var buf = new byte[4];
            rng.NextBytes(buf);
            return BitConverter.ToUInt32(buf, 0);
        }

        // ═══════════════════════════════════════════════════════════
        // 工具方法
        // ═══════════════════════════════════════════════════════════

        private static uint ReadU32BE(byte[] data, int offset)
        {
            return (uint)((data[offset] << 24) | (data[offset + 1] << 16) |
                          (data[offset + 2] << 8) | data[offset + 3]);
        }

        private static void WriteU32BE(byte[] data, int offset, uint value)
        {
            data[offset] = (byte)(value >> 24);
            data[offset + 1] = (byte)(value >> 16);
            data[offset + 2] = (byte)(value >> 8);
            data[offset + 3] = (byte)value;
        }

        private static byte[] TrimTrailingZeros(byte[] data)
        {
            int end = data.Length;
            while (end > 0 && data[end - 1] == 0) end--;
            if (end == data.Length) return data;
            return SubArray(data, 0, end);
        }

        internal static byte[] Base64DecodeWithPadding(byte[] data)
        {
            var str = Encoding.ASCII.GetString(data);
            for (int pad = 0; pad < 4; pad++)
            {
                try
                {
                    return Convert.FromBase64String(str + new string('=', pad));
                }
                catch { }
            }
            return null;
        }
    }
}