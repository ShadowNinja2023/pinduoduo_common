using System;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// data_type=15 报文 es 字段编解码器 (libdyn_config.so 的 SecureNative.dsi 离线复刻)。
    ///
    /// es = 反篡改检测明文 JSON 与固定 RC4 keystream 逐字节 XOR 后 base64:
    /// <code>
    ///   明文 = {"p61":ts,"p62":{"0".."8":&lt;函数序言完整性&gt;},...,"p98":&lt;RSA签名&gt;,"p131":N}
    ///   es   = base64( 明文[i] XOR KS[i] )
    /// </code>
    ///
    /// keystream = 标准 RC4 PRGA (全指令 trace 逐字节坐实, 见 docs 18 §9):
    ///   S = S0 (256B 排列, trace 行7465535 后重建; RC4 key 硬编码在 so 内, 故 S0/流全局固定)
    ///   i=1, j=191, 首字节挂起索引 t=193:
    ///       emit S[t]
    ///       重复: i=(i+1)&amp;0xff; j=(j+S[i])&amp;0xff; swap S[i],S[j]; t=(S[i]+S[j])&amp;0xff; emit S[t]
    ///   验证: out0=S0[193]=0xBA, out1=S[201]=0xB9, out2=S[7]=0x17 ... 复现真机 921B es 全长明文。
    ///
    /// 与 <see cref="Type16Codec"/> 同族 (都是流/字节变换 + base64, 对称可逆, 无 per-台唯一 ID)。
    /// </summary>
    public static class Type15Codec
    {
        // RC4 PRGA 初始状态 (trace 坐实, 全局固定)
        private const int I0 = 1;
        private const int J0 = 191;
        private const int T0 = 193;

        /// <summary>RC4 初始 S-box (KSA 完成 + 首个 PRGA 步后的权威快照, 256B 排列)。</summary>
        public static readonly byte[] S0 = new byte[256]
        {
            0x82, 0x02, 0x33, 0x5B, 0x89, 0x27, 0xA0, 0x17, 0x39, 0xE8, 0x9A, 0x7E, 0x5E, 0xB6, 0x54, 0xD1,
            0xEC, 0x57, 0x63, 0x6C, 0xF1, 0x18, 0xDA, 0x20, 0x38, 0x7F, 0x86, 0xCE, 0x5A, 0xBE, 0x66, 0x2F,
            0x26, 0xF9, 0xB1, 0x45, 0xA3, 0x13, 0x9E, 0x41, 0x00, 0x4E, 0x6B, 0x7B, 0x58, 0x08, 0xC8, 0x36,
            0xA5, 0xAB, 0x30, 0x23, 0x43, 0x92, 0xF0, 0x11, 0x5F, 0xB2, 0x25, 0x5D, 0x8C, 0x04, 0x47, 0xF4,
            0xFC, 0xD2, 0x3E, 0xB3, 0x1B, 0x65, 0xAD, 0x6D, 0xCC, 0x4A, 0xBB, 0x29, 0x2C, 0xAC, 0x2B, 0xAA,
            0x97, 0x12, 0x69, 0x51, 0x05, 0x72, 0x9D, 0x32, 0xAE, 0x60, 0x35, 0xCB, 0x50, 0x56, 0x03, 0xFA,
            0x2A, 0x4D, 0x80, 0xF5, 0xE9, 0x3F, 0x1F, 0x84, 0x2E, 0x68, 0x61, 0xA2, 0x7D, 0xD9, 0x0C, 0xA7,
            0xFE, 0x15, 0x9C, 0x2D, 0x87, 0xF2, 0xBC, 0xCA, 0xDF, 0x7A, 0xBD, 0x0D, 0x77, 0xE4, 0xDD, 0x81,
            0x74, 0xCF, 0x6A, 0x16, 0x5C, 0xC6, 0x48, 0x6E, 0x49, 0xD7, 0x0E, 0x95, 0x53, 0x42, 0xC2, 0x9F,
            0xCD, 0xFB, 0xEA, 0x4C, 0x78, 0x73, 0xF3, 0xD6, 0x93, 0x21, 0x44, 0xB4, 0xED, 0x6F, 0xDC, 0x7C,
            0x1E, 0x91, 0xB8, 0x14, 0x37, 0x3B, 0x8A, 0x76, 0xC3, 0x0B, 0xE6, 0x4B, 0xA9, 0xDB, 0x67, 0x1D,
            0x4F, 0xF7, 0xB0, 0xE1, 0xEB, 0x09, 0xF8, 0x0F, 0xA8, 0xE0, 0x62, 0x3D, 0x31, 0xC5, 0xD4, 0xBF,
            0x79, 0xBA, 0xD0, 0xC7, 0xD5, 0x3C, 0xA6, 0x8B, 0x99, 0xB9, 0x90, 0xC0, 0xF6, 0x22, 0x64, 0x06,
            0xD3, 0x46, 0x3A, 0xD8, 0x8E, 0x28, 0xC1, 0xE5, 0x1A, 0x75, 0x1C, 0xE3, 0xA1, 0xFF, 0x59, 0x01,
            0x9B, 0xFD, 0xDE, 0x83, 0x07, 0xEF, 0xB7, 0x8F, 0x88, 0x40, 0x85, 0xC4, 0x8D, 0x24, 0x19, 0xEE,
            0x10, 0xE2, 0x96, 0x52, 0x71, 0x0A, 0xE7, 0xC9, 0x55, 0x70, 0x98, 0xAF, 0x34, 0xA4, 0xB5, 0x94,
        };

        /// <summary>生成 n 字节固定 keystream (标准 RC4 PRGA, 任意长度)。</summary>
        public static byte[] Keystream(int n)
        {
            var S = (byte[])S0.Clone();
            int i = I0, j = J0, t = T0;
            var outp = new byte[n];
            for (int k = 0; k < n; k++)
            {
                outp[k] = S[t];
                i = (i + 1) & 0xff;
                j = (j + S[i]) & 0xff;
                byte tmp = S[i]; S[i] = S[j]; S[j] = tmp;
                t = (S[i] + S[j]) & 0xff;
            }
            return outp;
        }

        /// <summary>解码: es(base64) → 明文 JSON。</summary>
        public static string Decode(string es)
        {
            byte[] raw = Convert.FromBase64String(es);
            byte[] ks = Keystream(raw.Length);
            byte[] pt = new byte[raw.Length];
            for (int i = 0; i < raw.Length; i++) pt[i] = (byte)(raw[i] ^ ks[i]);
            return Encoding.UTF8.GetString(pt);
        }

        /// <summary>编码 (mock): 明文 JSON → es(base64)。</summary>
        public static string Encode(string plaintext)
        {
            byte[] pt = Encoding.UTF8.GetBytes(plaintext);
            byte[] ks = Keystream(pt.Length);
            byte[] raw = new byte[pt.Length];
            for (int i = 0; i < pt.Length; i++) raw[i] = (byte)(pt[i] ^ ks[i]);
            return Convert.ToBase64String(raw);
        }

        // ===== 明文内加密子blob (p74/p75/p84/p93/p98): base64( 明文 XOR 逐字段固定keystream ) =====
        // keystream 逐字段固定、跨设备一致 (见 docs 19 §3), 由 Type15Baseline 提供。

        /// <summary>子blob 编码: 明文字符串 XOR 字段keystream → base64。明文长度须 ≤ keystream 长度。</summary>
        public static string EncodeSubBlob(string plaintext, byte[] keystream)
        {
            byte[] pt = Encoding.UTF8.GetBytes(plaintext);
            if (pt.Length > keystream.Length)
                throw new ArgumentException($"子blob 明文 {pt.Length}B 超过 keystream {keystream.Length}B");
            byte[] raw = new byte[pt.Length];
            for (int i = 0; i < pt.Length; i++) raw[i] = (byte)(pt[i] ^ keystream[i]);
            return Convert.ToBase64String(raw);
        }

        /// <summary>子blob 解码: base64 → XOR 字段keystream → 明文 (可解长度 = min)。</summary>
        public static string DecodeSubBlob(string b64, byte[] keystream)
        {
            byte[] raw = Convert.FromBase64String(b64);
            int n = Math.Min(raw.Length, keystream.Length);
            byte[] pt = new byte[n];
            for (int i = 0; i < n; i++) pt[i] = (byte)(raw[i] ^ keystream[i]);
            return Encoding.UTF8.GetString(pt);
        }
    }
}
