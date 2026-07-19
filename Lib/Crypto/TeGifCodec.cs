using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace PddLib.Crypto
{
    /// <summary>
    /// te.gif 加密上报编解码 (jadx 破解: ga1.a.a / ga1.c.a / basekit.util.i.b,
    /// 全解见 docs/06_behavior_log/02_full_flow_render_success_analysis.md §3)。
    ///
    ///   body = AES-128-GCM( GZIP( 明文 form ) )   (密文尾部 16B 为 GCM tag)
    ///   key  = hex("651"+"292"+ascii("3829d4a476c836260e246c37a4"))
    ///        = hex("6512923829d4a476c836260e246c37a4")   (16B, 硬编码)
    ///   IV   = 随机 16B → HTTP 头 nonce(hex)
    ///   tag  = 128 bit (TDnsSourceType.kDSourceSession)
    ///   明文 = 与 t.gif 完全同格式的 url-form (含 sctk 签名)。
    ///
    /// 端点 POST https://th.pinduoduo.com/te.gif, content-type application/octet-stream,
    /// 头 nonce/sver=0.0.1/t-len={密文长度}。专载传感器数据 (op=event, sub_op=sensor)。
    /// </summary>
    public static class TeGifCodec
    {
        // ga1.a: f60049b="651" + f60050c="292" + f60051d=ascii("3829d4a476c836260e246c37a4")
        private static readonly byte[] Key = Convert.FromHexString("6512923829d4a476c836260e246c37a4");
        private const int TagLen = 16; // 128 bit

        /// <summary>sver 头固定值 (ga1.a)。</summary>
        public const string Sver = "0.0.1";

        // ⚠ Java 用 16 字节 IV (GCMParameterSpec 允许任意长度, J0 走 GHASH 派生);
        //   .NET 内置 AesGcm 只支持 12 字节 nonce → 改用 BouncyCastle GcmBlockCipher。

        /// <summary>加密: 明文 form 串 → (te.gif body 字节 = 密文||tag, nonce=IV 的 hex)。</summary>
        public static (byte[] body, string nonceHex) Encrypt(string plaintext)
        {
            byte[] gz = Gzip(Encoding.UTF8.GetBytes(plaintext));
            byte[] iv = RandomNumberGenerator.GetBytes(16);
            byte[] body = GcmProcess(true, gz, iv);   // BC 输出 = 密文 || tag (同 Java doFinal)
            return (body, Convert.ToHexString(iv).ToLowerInvariant());
        }

        /// <summary>解密 (自检 / 验证真机 te.gif): body 字节 + nonce hex → 明文 form 串。</summary>
        public static string Decrypt(byte[] body, string nonceHex)
        {
            byte[] iv = Convert.FromHexString(nonceHex);
            byte[] gz = GcmProcess(false, body, iv);
            return Encoding.UTF8.GetString(Gunzip(gz));
        }

        private static byte[] GcmProcess(bool forEncrypt, byte[] input, byte[] iv)
        {
            var gcm = new GcmBlockCipher(new AesEngine());
            gcm.Init(forEncrypt, new AeadParameters(new KeyParameter(Key), TagLen * 8, iv));
            var outBuf = new byte[gcm.GetOutputSize(input.Length)];
            int len = gcm.ProcessBytes(input, 0, input.Length, outBuf, 0);
            len += gcm.DoFinal(outBuf, len);
            if (len == outBuf.Length) return outBuf;
            var trimmed = new byte[len];
            Buffer.BlockCopy(outBuf, 0, trimmed, 0, len);
            return trimmed;
        }

        private static byte[] Gzip(byte[] data)
        {
            using var ms = new MemoryStream();
            using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true))
                gz.Write(data, 0, data.Length);
            return ms.ToArray();
        }

        private static byte[] Gunzip(byte[] data)
        {
            using var ins = new MemoryStream(data);
            using var gz = new GZipStream(ins, CompressionMode.Decompress);
            using var outs = new MemoryStream();
            gz.CopyTo(outs);
            return outs.ToArray();
        }
    }
}
