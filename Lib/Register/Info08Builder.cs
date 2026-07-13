using System.Collections.Generic;
using System.Text;
using PddLib.Crypto;

namespace PddLib.Register
{
    /// <summary>08 报文 info 生成选项。</summary>
    public sealed class Info08Options
    {
        /// <summary>证书链 (键 "0","1",... 顺序), 每项 = URLEncode(base64(attestation cert DER))。
        /// null 时用 <see cref="Info08Baseline.CertChain"/> 基线。</summary>
        public IReadOnlyList<string>? CertChain { get; set; }
    }

    /// <summary>
    /// 组装 08 报文 info 字段 (SecureNative.atn 离线复刻, 见 docs 21)。
    ///
    /// info = base64( 明文String XOR RC4 keystream ), 明文 = {"0":"&lt;c0&gt;","1":"&lt;c1&gt;",...}
    ///   c_i = URLEncode(base64( X.509 Android 密钥认证证书 DER )) —— 证书链 (leaf+中间+根)。
    /// 默认复用基线证书链 (per-台, mock 低风险); 传 <see cref="Info08Options.CertChain"/> 可换设备证书。
    /// </summary>
    public static class Info08Builder
    {
        /// <summary>组装 info 明文 JSON: {"0":"c0","1":"c1",...} (无空格, 键从 0 递增)。</summary>
        public static string BuildPlaintext(Info08Options? opts = null)
        {
            var chain = opts?.CertChain ?? Info08Baseline.CertChain;
            var sb = new StringBuilder(8192);
            sb.Append('{');
            for (int i = 0; i < chain.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append('"').Append(i).Append("\":\"").Append(chain[i]).Append('"');
            }
            sb.Append('}');
            return sb.ToString();
        }

        /// <summary>生成 info (base64 密文): 明文 → Type21Codec RC4 XOR → base64。</summary>
        public static string BuildInfo(Info08Options? opts = null)
            => Type21Codec.Encode(BuildPlaintext(opts));
    }
}
