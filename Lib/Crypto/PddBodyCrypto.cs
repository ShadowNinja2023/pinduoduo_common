using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// PDD 上报 body 的混合加密 (SecureNative.ng / 同套 AES+RSA)。
    ///
    /// 输出格式:
    ///   {"key":"&lt;base64 RSA(random32)&gt;","data":"&lt;base64 AES_CBC(plaintext)&gt;"}
    ///
    /// 加密参数 (来自 docs/01_so_analysis/PDD-Encryption-Algorithm.md):
    ///   - random_key_gen: 生成 32 字节随机 (上线用真随机; 验证用固定值)
    ///   - AES-128-CBC: Key = random[0:16], IV = 全零 16B, PKCS7
    ///   - RSA-1024 PKCS#1 v1.5: 加密完整 32 字节 random, E = 65537
    ///
    /// 抓包解密用的固定 random (hook_fix_aes_key 固定值):
    ///   01 02 03 .. 20
    /// </summary>
    public static class PddBodyCrypto
    {
        /// <summary>抓包 hook 固定的 32 字节 random (仅用于离线验证比对)</summary>
        public static readonly byte[] FixedRandom32 = BuildFixedRandom();

        private static byte[] BuildFixedRandom()
        {
            var r = new byte[32];
            for (int i = 0; i < 32; i++) r[i] = (byte)(i + 1);
            return r;
        }

        // ==================== RSA-1024 公钥 (新版 8.8.0, Frida 实测提取) ====================
        // N (1024-bit), E = 65537。来源: traces/rsa_frida.log (sub_16350C 模数 a3, 8 次一致)
        // 旧版 N (83baf16b...) 服务端已不认; 此为当前生产公钥。
        private const string RsaNHex =
            "c21da1b2c66236e7cadcf82c04b3dd18a41fa9fe99e23388de4ab46636e4dd02" +
            "96725d0a699e58544fddddcf251986230d03d7451a25eb5c6232c904cdc7bb6e" +
            "4cb9f18126fb6e83f1a59b5da14917838e82938e71088c68356ea062a73d83ee" +
            "44db698fa6cab356e0881d68b13aa8f87543f0d721cdd9b687a0175ee030479b";
        private const int RsaE = 65537;

        // ==================== 顶层 API ====================

        /// <summary>
        /// 加密明文为 PDD body 包 {"key":..,"data":..}。
        /// </summary>
        /// <param name="plaintext">待加密明文字节 (如 url-encoded 表单)</param>
        /// <param name="random32">32 字节随机; null 则用 RNG 真随机生成</param>
        /// <returns>{"key":"...","data":"..."} JSON 字符串</returns>
        public static string EncryptPacket(byte[] plaintext, byte[]? random32 = null)
        {
            random32 ??= RandomBytes(32);
            if (random32.Length != 32)
                throw new ArgumentException("random32 必须是 32 字节", nameof(random32));

            byte[] aesKey = new byte[16];
            Array.Copy(random32, aesKey, 16);

            string dataB64 = Convert.ToBase64String(AesCbcEncrypt(plaintext, aesKey));
            string keyB64 = Convert.ToBase64String(RsaEncryptPkcs1(random32));

            // PDD 用 sprintf 拼装, key 在前 data 在后
            return $"{{\"key\":\"{keyB64}\",\"data\":\"{dataB64}\"}}";
        }

        /// <summary>仅返回 AES 密文的 base64 (用于离线逐字节比对样本 data 字段)</summary>
        public static string EncryptData(byte[] plaintext, byte[] aesKey16)
            => Convert.ToBase64String(AesCbcEncrypt(plaintext, aesKey16));

        /// <summary>
        /// 用"固定 random + 现成 RSA key 字段"加密。
        ///
        /// 原理: 抓包 hook 把 random 固定为 0102..20, 样本 body 的 key 字段 =
        /// RSA(0102..20) 且用的是真机真实公钥。复用该 key 字段 + 固定 AES key(0102..0F10),
        /// 服务端用私钥能正确解出 AES key 并解开我们的 data —— 绕过对 RSA 公钥 N 的依赖。
        /// </summary>
        /// <param name="plaintext">待加密明文</param>
        /// <param name="capturedKeyFieldB64">样本 body 的 key 字段 (RSA(固定random) 的 base64, 不含转义)</param>
        public static string EncryptPacketWithCapturedKey(byte[] plaintext, string capturedKeyFieldB64)
        {
            byte[] aesKey = new byte[16];
            Array.Copy(FixedRandom32, aesKey, 16);
            string dataB64 = Convert.ToBase64String(AesCbcEncrypt(plaintext, aesKey));
            return $"{{\"key\":\"{capturedKeyFieldB64}\",\"data\":\"{dataB64}\"}}";
        }

        // ==================== AES-128-CBC ====================

        public static byte[] AesCbcEncrypt(byte[] plaintext, byte[] key16)
        {
            using var aes = Aes.Create();
            aes.Key = key16;
            aes.IV = new byte[16];
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        public static byte[] AesCbcDecrypt(byte[] ciphertext, byte[] key16)
        {
            using var aes = Aes.Create();
            aes.Key = key16;
            aes.IV = new byte[16];
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using var dec = aes.CreateDecryptor();
            return dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }

        // ==================== RSA-1024 PKCS#1 v1.5 ====================

        /// <summary>
        /// RSA PKCS#1 v1.5 加密 (公钥操作)。输出 128 字节 (1024-bit)。
        /// 自己实现 padding + modpow, 因为 .NET RSA 不直接吃裸 N/E。
        /// </summary>
        public static byte[] RsaEncryptPkcs1(byte[] message)
        {
            int k = 128; // 1024-bit = 128 字节
            if (message.Length > k - 11)
                throw new ArgumentException("消息过长");

            // EM = 0x00 || 0x02 || PS(非零随机, >=8B) || 0x00 || M
            byte[] em = new byte[k];
            em[0] = 0x00;
            em[1] = 0x02;
            int psLen = k - 3 - message.Length;
            byte[] ps = new byte[psLen];
            using (var rng = RandomNumberGenerator.Create())
            {
                // PS 必须非零
                for (int i = 0; i < psLen; i++)
                {
                    byte b;
                    do { b = RandomByte(rng); } while (b == 0);
                    ps[i] = b;
                }
            }
            Array.Copy(ps, 0, em, 2, psLen);
            em[2 + psLen] = 0x00;
            Array.Copy(message, 0, em, 3 + psLen, message.Length);

            BigInteger m = OsToBig(em);
            BigInteger n = ParseHexBig(RsaNHex);
            BigInteger c = BigInteger.ModPow(m, RsaE, n);
            return BigToOs(c, k);
        }

        // ==================== 大数/字节转换 ====================

        private static BigInteger ParseHexBig(string hex)
        {
            // 加前导 00 保证为正数
            return BigInteger.Parse("0" + hex, System.Globalization.NumberStyles.HexNumber);
        }

        /// <summary>大端字节数组 -> 正 BigInteger</summary>
        private static BigInteger OsToBig(byte[] os)
            => new BigInteger(os, isUnsigned: true, isBigEndian: true);

        /// <summary>BigInteger -> 固定长度大端字节数组 (左侧补零)</summary>
        private static byte[] BigToOs(BigInteger v, int len)
        {
            byte[] be = v.ToByteArray(isUnsigned: true, isBigEndian: true);
            if (be.Length == len) return be;
            if (be.Length > len)
                throw new InvalidOperationException($"RSA 输出 {be.Length} 字节超过 {len}");
            byte[] outp = new byte[len];
            Array.Copy(be, 0, outp, len - be.Length, be.Length);
            return outp;
        }

        // ==================== 随机 ====================

        private static byte[] RandomBytes(int n)
        {
            byte[] b = new byte[n];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(b);
            return b;
        }

        private static byte RandomByte(RandomNumberGenerator rng)
        {
            byte[] one = new byte[1];
            rng.GetBytes(one);
            return one[0];
        }
    }
}
