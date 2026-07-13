using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// PDD 登录类接口的 anti-token (JNI 函数 info2, 前缀 "2af")。
    ///
    /// 算法:  "2af" + Base64( AES-128-CBC( GZIP( TLV明文 ) ) )
    ///   Key = "pdd_aes_180121_1" (hex 7064645f6165735f3138303132315f31, 同 info4)
    ///   IV  = 全 0 (16 字节)          ← 注意与 info4 一致, 全零
    ///   Padding = PKCS7
    ///   压缩 = 标准 GZIP (java.util.zip.GZIPOutputStream)
    ///
    /// TLV 明文帧 (见 Info2Tlv):
    ///   [4B magic 01 00 00 00][u16-BE 总长][ 条目* ]
    ///   条目 = [u16-BE entryLen][u8 group][u8 index][value(entryLen-2)]
    ///
    /// 与 info4 (2ag) 的区别: info4 无 GZIP、明文是 30B 定长结构、IV 也是全 0;
    /// info2 (2af) 多了一层 GZIP, 明文是设备信息大 TLV。
    ///
    /// 安全: 仅用于授权的逆向研究与自有设备登录联调。
    /// </summary>
    public static class Info2Codec
    {
        private static readonly byte[] Key =
            Convert.FromHexString("7064645f6165735f3138303132315f31");  // "pdd_aes_180121_1"
        private static readonly byte[] Iv = new byte[16];               // 全 0
        private const string Prefix = "2af";

        // ==================== 顶层 API ====================

        /// <summary>构造 anti-token: TLV 明文 → GZIP → AES-CBC → base64 → "2af" 前缀。</summary>
        public static string Encrypt(byte[] tlvPlaintext)
        {
            byte[] gz = Gzip(tlvPlaintext);
            byte[] ct = AesCbcEncrypt(gz);
            return Prefix + Convert.ToBase64String(ct);
        }

        /// <summary>解 anti-token: 去 "2af" → base64 → AES-CBC 解密 → GUNZIP → TLV 明文。</summary>
        public static byte[] Decrypt(string antiToken)
        {
            if (antiToken == null || !antiToken.StartsWith(Prefix))
                throw new ArgumentException("anti-token 缺少 '2af' 前缀", nameof(antiToken));
            byte[] ct = Convert.FromBase64String(antiToken.Substring(Prefix.Length));
            byte[] gz = AesCbcDecrypt(ct);
            return Gunzip(gz);
        }

        // ==================== AES-128-CBC (key=pdd_aes_180121_1, IV=0, PKCS7) ====================

        public static byte[] AesCbcEncrypt(byte[] plaintext)
        {
            using var aes = Aes.Create();
            aes.Key = Key; aes.IV = Iv;
            aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
            using var enc = aes.CreateEncryptor();
            return enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        public static byte[] AesCbcDecrypt(byte[] ciphertext)
        {
            using var aes = Aes.Create();
            aes.Key = Key; aes.IV = Iv;
            aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
            using var dec = aes.CreateDecryptor();
            return dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
        }

        // ==================== GZIP (标准) ====================

        public static byte[] Gzip(byte[] data)
        {
            using var ms = new MemoryStream();
            using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
                gz.Write(data, 0, data.Length);
            return ms.ToArray();
        }

        public static byte[] Gunzip(byte[] gz)
        {
            using var ms = new MemoryStream(gz);
            using var gzs = new GZipStream(ms, CompressionMode.Decompress);
            using var outMs = new MemoryStream();
            gzs.CopyTo(outMs);
            return outMs.ToArray();
        }
    }
}
