using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PddLib.Crypto
{
    /// <summary>
    /// PDD DeviceNative.info4() 加解密实现
    /// 
    /// 算法: "2ag" + Base64(AES-128-CBC(plaintext))
    /// Key:  pdd_aes_180121_1
    /// IV:   全零 16 bytes
    /// 
    /// 明文结构 (30 或 30+N bytes):
    ///   [0]      serverId 原始长度
    ///   [1]      类型枚举 (0x1F=含serverId, 0x0F=不含)
    ///   [2:10]   Android ID (hex→raw 8 bytes)
    ///   [10:18]  时间戳 BE int64 (毫秒)
    ///   [18:22]  lrand48(srand48(tv_sec))
    ///   [22:26]  lrand48(srand48(tv_usec))
    ///   [26:30]  UUID.hashCode() BE int32
    ///   [30:N]   serverId ASCII (仅当 [1]=0x1F)
    /// </summary>
    public static class Info4Codec
    {
        private static readonly byte[] Key = Encoding.ASCII.GetBytes("pdd_aes_180121_1");
        private static readonly byte[] IV = new byte[16];
        private const string Prefix = "2ag";
        private const int MinServerIdLen = 8;

        // ==================== srand48 / lrand48 ====================

        /// <summary>
        /// POSIX srand48 + lrand48 单次调用
        /// LCG: state = (0x5DEECE66D * state + 0xB) mod 2^48
        /// lrand48 返回 state >> 17 (高31位)
        /// </summary>
        public static uint Lrand48(long seed)
        {
            // srand48: state = (seed << 16) | 0x330E
            ulong state = (((ulong)(seed & 0xFFFFFFFF)) << 16) | 0x330E;
            // LCG 迭代一次
            state = (0x5DEECE66DUL * state + 0xB) & 0xFFFFFFFFFFFFUL;
            // lrand48: 返回高31位
            return (uint)(state >> 17);
        }

        // ==================== 明文构建 ====================

        public static byte[] BuildPlaintext(
            string androidIdHex,   // 16位 hex, 如 "6ecc7a575d3f8735"
            long timestampMs,      // Java 毫秒时间戳
            string serverId,       // 服务器下发 ID
            int uuidHashCode,      // UUID.randomUUID().toString().replace("-","").hashCode()
            long tvSec,            // gettimeofday tv_sec
            long tvUsec)           // gettimeofday tv_usec (0~999999)
        {
            bool hasSid = serverId != null && serverId.Length >= MinServerIdLen;
            byte[] sidBytes = hasSid ? Encoding.ASCII.GetBytes(serverId) : Array.Empty<byte>();
            int totalLen = 30 + (hasSid ? sidBytes.Length : 0);

            byte[] buf = new byte[totalLen];
            int pos = 0;

            // [0] serverId 原始长度
            buf[pos++] = (byte)(serverId?.Length ?? 0);

            // [1] 类型枚举
            buf[pos++] = hasSid ? (byte)0x1F : (byte)0x0F;

            // [2:10] Android ID (hex → raw 8 bytes)
            byte[] aid = HexToBytes(androidIdHex);
            Array.Copy(aid, 0, buf, pos, 8);
            pos += 8;

            // [10:18] 时间戳 BE int64
            WriteBE64(buf, pos, timestampMs);
            pos += 8;

            // [18:22] lrand48(srand48(tv_sec))
            WriteBE32(buf, pos, Lrand48(tvSec));
            pos += 4;

            // [22:26] lrand48(srand48(tv_usec))
            WriteBE32(buf, pos, Lrand48(tvUsec));
            pos += 4;

            // [26:30] UUID hashCode BE int32
            WriteBE32(buf, pos, (uint)uuidHashCode);
            pos += 4;

            // [30:N] serverId ASCII
            if (hasSid)
                Array.Copy(sidBytes, 0, buf, pos, sidBytes.Length);

            return buf;
        }

        /// <summary>
        /// 简易版 — 自动处理 gettimeofday 和 UUID hashCode
        /// </summary>
        public static byte[] BuildPlaintext(
            string androidIdHex,
            long timestampMs,
            string serverId,
            Guid uuid)
        {
            // Java: UUID.randomUUID().toString().replace("-","").hashCode()
            int uuidHashCode = JavaStringHashCode(uuid.ToString("N"));

            // 用当前时间模拟 gettimeofday
            var now = DateTimeOffset.UtcNow;
            long tvSec = now.ToUnixTimeSeconds();
            long tvUsec = (now.ToUnixTimeMilliseconds() % 1000) * 1000
                        + (now.Ticks % TimeSpan.TicksPerMillisecond) / (TimeSpan.TicksPerMillisecond / 1000);

            return BuildPlaintext(androidIdHex, timestampMs, serverId, uuidHashCode, tvSec, tvUsec);
        }

        /// <summary>
        /// Java String.hashCode() 实现: s[0]*31^(n-1) + s[1]*31^(n-2) + ... + s[n-1]
        /// </summary>
        public static int JavaStringHashCode(string s)
        {
            int h = 0;
            foreach (char c in s)
                h = h * 31 + c;
            return h;
        }

        // ==================== 加密 ====================

        public static string Encrypt(byte[] plaintext)
        {
            using var aes = Aes.Create();
            aes.Key = Key;
            aes.IV = IV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var enc = aes.CreateEncryptor();
            byte[] ct = enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
            return Prefix + Convert.ToBase64String(ct);
        }

        // ==================== 解密 ====================

        public static byte[] Decrypt(string info4Result)
        {
            if (!info4Result.StartsWith(Prefix))
                throw new ArgumentException("Missing '2ag' prefix");

            byte[] ct = Convert.FromBase64String(info4Result.Substring(Prefix.Length));

            using var aes = Aes.Create();
            aes.Key = Key;
            aes.IV = IV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var dec = aes.CreateDecryptor();
            return dec.TransformFinalBlock(ct, 0, ct.Length);
        }

        // ==================== 解析 ====================

        public static void Parse(byte[] pt)
        {
            Console.WriteLine($"[0]      sid_len:    {pt[0]}");
            Console.WriteLine($"[1]      type:       0x{pt[1]:X2} ({(pt[1] == 0x1F ? "has serverId" : "no serverId")})");
            Console.WriteLine($"[2:10]   android_id: {BytesToHex(pt, 2, 8)}");

            long ts = ReadBE64(pt, 10);
            Console.WriteLine($"[10:18]  timestamp:  {ts} ({DateTimeOffset.FromUnixTimeMilliseconds(ts):u})");
            Console.WriteLine($"[18:22]  lr48_sec:   {BytesToHex(pt, 18, 4)}");
            Console.WriteLine($"[22:26]  lr48_usec:  {BytesToHex(pt, 22, 4)}");

            int hc = (int)ReadBE32(pt, 26);
            Console.WriteLine($"[26:30]  uuid_hash:  {BytesToHex(pt, 26, 4)} = {hc}");

            if (pt.Length > 30)
            {
                string sid = Encoding.ASCII.GetString(pt, 30, pt.Length - 30);
                Console.WriteLine($"[30:{pt.Length}]  serverId:   \"{sid}\"");
            }
        }

        // ==================== 辅助方法 ====================

        private static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return bytes;
        }

        private static string BytesToHex(byte[] buf, int offset, int len)
        {
            var sb = new StringBuilder(len * 2);
            for (int i = 0; i < len; i++)
                sb.Append(buf[offset + i].ToString("x2"));
            return sb.ToString();
        }

        private static void WriteBE64(byte[] buf, int offset, long val)
        {
            for (int i = 7; i >= 0; i--)
            {
                buf[offset + i] = (byte)(val & 0xFF);
                val >>= 8;
            }
        }

        private static void WriteBE32(byte[] buf, int offset, uint val)
        {
            buf[offset] = (byte)(val >> 24);
            buf[offset + 1] = (byte)(val >> 16);
            buf[offset + 2] = (byte)(val >> 8);
            buf[offset + 3] = (byte)(val);
        }

        private static long ReadBE64(byte[] buf, int offset)
        {
            long val = 0;
            for (int i = 0; i < 8; i++)
                val = (val << 8) | buf[offset + i];
            return val;
        }

        private static uint ReadBE32(byte[] buf, int offset)
        {
            return ((uint)buf[offset] << 24) | ((uint)buf[offset + 1] << 16)
                 | ((uint)buf[offset + 2] << 8) | buf[offset + 3];
        }
    }

}
