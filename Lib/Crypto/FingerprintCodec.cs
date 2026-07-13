using System;
using System.Text;
using System.Text.Json;

namespace PddLib.Crypto
{
    /// <summary>
    /// 登录类接口 body 内 fingerprint / touchevent 字段的加密信封。
    ///
    /// 信封:  {"key":"&lt;base64 RSA(random32)&gt;","data":"&lt;base64 AES-128-CBC(GZIP(json))&gt;"}
    ///   - 与 meta_info 的 ng() / PddBodyCrypto 同族, 唯一差别: 明文 JSON 先 GZIP。
    ///   - AES Key = random[0:16], IV = 全 0, PKCS7; RSA-1024 PKCS#1 v1.5 加密完整 32B random。
    ///
    /// 详见 docs/04_device_register/15_fingerprint_touchevent_analysis.md。
    /// </summary>
    public static class FingerprintCodec
    {
        /// <summary>把明文 JSON 加密成 fingerprint/touchevent 字段值 {"key","data"}。</summary>
        /// <param name="json">明文 JSON 字符串</param>
        /// <param name="random32">32 字节随机; null=真随机 (上线)。传固定值可复刻抓包。</param>
        public static string Encrypt(string json, byte[]? random32 = null)
        {
            byte[] gz = Info2Codec.Gzip(Encoding.UTF8.GetBytes(json));
            return PddBodyCrypto.EncryptPacket(gz, random32);
        }

        /// <summary>
        /// 解 fingerprint/touchevent 字段值 (需已知 AES key, 如抓包固定 key 0102..0f10)。
        /// 返回明文 JSON 字符串。
        /// </summary>
        public static string Decrypt(string packetJson, byte[] aesKey16)
        {
            using var doc = JsonDocument.Parse(packetJson);
            string dataB64 = doc.RootElement.GetProperty("data").GetString() ?? "";
            byte[] gz = PddBodyCrypto.AesCbcDecrypt(Convert.FromBase64String(dataB64), aesKey16);
            byte[] raw = Info2Codec.Gunzip(gz);
            return Encoding.UTF8.GetString(raw);
        }

        /// <summary>抓包固定 key (hook random=0102..20) 的 AES key = random[0:16]。</summary>
        public static byte[] FixedAesKey()
        {
            var k = new byte[16];
            for (int i = 0; i < 16; i++) k[i] = (byte)(i + 1);
            return k;
        }
    }
}
