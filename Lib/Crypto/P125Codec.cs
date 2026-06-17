using System;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// p125 生成实现 — 逆向自 libpdd_secure.so (sub_18DAF4, RC4+base64)
    ///
    /// 公式:
    ///   p125 = Base64_std( RC4_standard( uuid_string_36B, key="d99aKms9tzr9cp9v" ) )
    ///
    /// - 明文 = 一个独立的标准 UUID 字符串 (36 字符, 含连字符), 与报文 uuid 字段无关。
    /// - RC4 = 标准 RC4 (非 x-p1 的 +0x1A 变体), key = ASCII "d99aKms9tzr9cp9v" (16 字节硬编码)。
    /// - 36 字节 → base64 48 字符 (恰好整除, 无 '=' 填充), 与样本一致。
    /// - 不含 android_id/oaid → 无交叉校验风险; mock 每台设备自生成一个新 UUID 加密即可。
    ///
    /// 验证: RC4 对称, 解密样本密文得回 UUID 字符串 (scripts 同 p49/p30 那套)。
    /// </summary>
    public static class P125Codec
    {
        /// <summary>p125 专用 RC4 key (硬编码, key表@0x7188ca72a0)</summary>
        public static readonly byte[] Rc4Key = Encoding.ASCII.GetBytes("d99aKms9tzr9cp9v");

        /// <summary>由给定 UUID 字符串生成 p125 (base64)。</summary>
        public static string Generate(string uuidString, byte[]? key = null)
        {
            byte[] ct = P30Codec.Rc4(key ?? Rc4Key, Encoding.ASCII.GetBytes(uuidString));
            return Convert.ToBase64String(ct);
        }

        /// <summary>生成一个随机 UUID 并加密为 p125 (mock 每台设备调用一次)。</summary>
        public static string GenerateRandom(byte[]? key = null)
            => Generate(Guid.NewGuid().ToString(), key);

        /// <summary>解密 p125 base64 → UUID 字符串 (验证/分析用)。</summary>
        public static string Decrypt(string p125Base64, byte[]? key = null)
        {
            string padded = p125Base64;
            int mod = padded.Length % 4;
            if (mod != 0) padded += new string('=', 4 - mod);
            byte[] pt = P30Codec.Rc4(key ?? Rc4Key, Convert.FromBase64String(padded));
            return Encoding.ASCII.GetString(pt);
        }
    }
}
