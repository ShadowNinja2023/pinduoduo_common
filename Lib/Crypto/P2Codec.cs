using System;
using System.Security.Cryptography;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// 04/06 报文 p2 (Android KeyStore Attestation 扩展 DER) 的唯一值随机化。
    ///
    /// p2 = url-encode( 64列换行的 base64( attestation 扩展 DER ) )。
    /// DER 结构 (KeyDescription, 无签名, 仅扩展内容): attestationVersion/securityLevel/
    ///   challenge("default_c" 固定)/uniqueId/softwareEnforced(含 attestationApplicationId=包名+签名SHA256)/
    ///   teeEnforced(purpose/algo/keySize/digest/rootOfTrust(verifiedBootKey+deviceLocked+bootState+verifiedBootHash)/os版本...)。
    ///
    /// 参考 EsDecrypt/C662Patcher.RandomizeUniqueValues 思路: 只随机"每台设备唯一"的定长字段,
    /// 不动包名/签名/结构 → 保持 DER 合法且看似真实, 每台 mock 的 p2 不同 (避免固定指纹)。
    ///
    /// 本实现随机化 rootOfTrust 的两块 32B: <b>verifiedBootKey</b> 与 <b>verifiedBootHash</b>
    /// (真机的 verified boot 根信任, 天然每台不同), 定位标记 <c>bf 85 40</c>。
    /// 保留: challenge / 包名 / 签名 digest / 版本补丁 / deviceLocked / verifiedBootState。
    /// </summary>
    public static class P2Codec
    {
        // rootOfTrust 序列标记: bf 85 40 <len> 30 <len> 04 20 <32B verifiedBootKey>
        //   ... 01 01 ff (deviceLocked) 0a 01 XX (verifiedBootState) 04 20 <32B verifiedBootHash>
        private static readonly byte[] RootOfTrustTag = { 0xbf, 0x85, 0x40 };

        /// <summary>
        /// 随机化 p2 (url-encoded 线格式) 的 verifiedBootKey/verifiedBootHash。
        /// 失败或结构不符时返回原值。
        /// </summary>
        public static string RandomizeUniqueValues(string p2Wire)
        {
            if (string.IsNullOrEmpty(p2Wire)) return p2Wire;
            byte[] der;
            try
            {
                string b64 = Uri.UnescapeDataString(p2Wire).Replace("\n", "").Replace("\r", "");
                der = Convert.FromBase64String(b64);
            }
            catch { return p2Wire; }

            int rot = IndexOf(der, RootOfTrustTag, 0);
            if (rot < 0) return p2Wire;

            // bf 85 40 | len(1) | 30 | len(1) | 04 20 | key(32) | 01 01 ff | 0a 01 XX | 04 20 | hash(32)
            int p = rot + 3;
            if (p + 4 >= der.Length) return p2Wire;
            p += 1;                       // 外层 len
            if (der[p] != 0x30) return p2Wire; p += 1;  // SEQUENCE
            p += 1;                       // 内层 len
            if (der[p] != 0x04 || der[p + 1] != 0x20) return p2Wire; p += 2;  // OCTET STRING 32
            int keyOff = p;
            if (keyOff + 32 + 6 + 2 + 32 > der.Length) return p2Wire;
            int hashOff = keyOff + 32 + 3 /*01 01 ff*/ + 3 /*0a 01 XX*/ + 2 /*04 20*/;
            // 校验 hash 前的 04 20
            if (der[hashOff - 2] != 0x04 || der[hashOff - 1] != 0x20) return p2Wire;

            RandomNumberGenerator.Fill(der.AsSpan(keyOff, 32));   // verifiedBootKey
            RandomNumberGenerator.Fill(der.AsSpan(hashOff, 32));  // verifiedBootHash

            // 重新 base64 (64列 + '\n' 换行, 末尾 '\n', 复刻真机 MIME 格式) → url-encode
            string wrapped = WrapBase64(Convert.ToBase64String(der), 64);
            return JavaUrlEncode(wrapped);
        }

        private static int IndexOf(byte[] hay, byte[] needle, int start)
        {
            for (int i = start; i <= hay.Length - needle.Length; i++)
            {
                bool ok = true;
                for (int j = 0; j < needle.Length; j++)
                    if (hay[i + j] != needle[j]) { ok = false; break; }
                if (ok) return i;
            }
            return -1;
        }

        private static string WrapBase64(string b64, int lineLen)
        {
            var sb = new StringBuilder(b64.Length + b64.Length / lineLen + 2);
            for (int i = 0; i < b64.Length; i += lineLen)
                sb.Append(b64, i, Math.Min(lineLen, b64.Length - i)).Append('\n');
            return sb.ToString();  // 末尾带一个 '\n' (与样本一致)
        }

        /// <summary>Java URLEncoder 等价: 空格→+, 字母数字与 -_.* 保留, 其余 %XX (大写); '\n'→%0A。</summary>
        private static string JavaUrlEncode(string s)
        {
            var sb = new StringBuilder(s.Length * 2);
            foreach (byte b in Encoding.UTF8.GetBytes(s))
            {
                char c = (char)b;
                if (c == ' ') sb.Append('+');
                else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                         c == '-' || c == '_' || c == '.' || c == '*') sb.Append(c);
                else sb.Append('%').Append(b.ToString("X2"));
            }
            return sb.ToString();
        }
    }
}
