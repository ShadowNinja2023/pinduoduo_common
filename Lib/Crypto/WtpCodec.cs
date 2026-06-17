using System;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// 05 报文 wtp 字段编解码器 (libdyncommon SE.wtp() 的离线复刻)。
    ///
    /// wtp = 上报客户端独立解析 <c>strc.pinduoduo.com</c> 得到的真实可达 IP
    /// (反代理 / 反 DNS 劫持校验, 服务端比对其合法性与连接源一致性)。
    ///
    /// 结构 (trace + live hook 全验证, 见 docs 12_request05 §5.8):
    /// <code>
    ///   明文 = "0|" + IP + "|0"            (len = L, 如 "0|180.139.62.90|0" L=17)
    ///   tag  = NUL 插入位置 ∈ [1, L)        (app = per-call 随机 w0 mod L; 非校验和)
    ///   buf  = 明文在 tag 处插入一个 0x00    (L+1 字节)
    ///   K    = 每次随机字节
    ///   载荷 = buf XOR K                    (buf[0]='0' → K = 载荷[0]^'0' 自描述; 载荷[tag]=K)
    ///   容器 = 0f c1 00 00 04 04 00 | tag | 载荷
    ///   wtp  = base64(容器)
    /// </code>
    /// 解码: K = 载荷[0]^'0' → buf = 载荷^K → 删除 buf[tag] 处的 NUL → "0|IP|0"。
    ///
    /// 验证: 用固定 (tag,key) 逐字节复现两个真实样本 PASS (见 scripts/wtp_codec.py / MockCompare 第12节)。
    /// </summary>
    public static class WtpCodec
    {
        /// <summary>libdyncommon 子编码容器头 (恒定)。</summary>
        public static readonly byte[] Header = { 0x0F, 0xC1, 0x00, 0x00, 0x04, 0x04, 0x00 };

        /// <summary>
        /// trace/hook 实测的真实解析 IP (strc.pinduoduo.com)。
        /// ⚠ 这是网络相关值: 正式上线应按 mock 出口实际解析结果替换 (CDN 按地区/时间变)。
        /// </summary>
        public const string DefaultIp = "180.139.62.90";

        /// <summary>
        /// 生成 wtp (base64)。tag/key 不传则随机 (与真机一致, 每次不同但解码同 IP)。
        /// </summary>
        /// <param name="ip">strc.pinduoduo.com 的解析 IP (点分十进制)</param>
        /// <param name="tag">NUL 插入位置 ∈[1,L); null 随机</param>
        /// <param name="key">XOR key 0..255; null 随机</param>
        public static string Encode(string ip, int? tag = null, int? key = null)
        {
            byte[] pt = Encoding.ASCII.GetBytes("0|" + ip + "|0");
            int L = pt.Length;
            if (L < 2) throw new ArgumentException("ip 非法", nameof(ip));

            int t = tag ?? Random.Shared.Next(1, L);          // ∈[1,L): 不能为0 (须保 buf[0]='0')
            if (t < 1 || t >= L) throw new ArgumentOutOfRangeException(nameof(tag));
            int k = key ?? Random.Shared.Next(0, 256);

            // 在位置 t 插入一个 0x00
            byte[] buf = new byte[L + 1];
            Array.Copy(pt, 0, buf, 0, t);
            buf[t] = 0x00;
            Array.Copy(pt, t, buf, t + 1, L - t);

            // 整体 XOR K
            byte[] payload = new byte[buf.Length];
            for (int i = 0; i < buf.Length; i++) payload[i] = (byte)(buf[i] ^ k);

            byte[] raw = new byte[Header.Length + 1 + payload.Length];
            Array.Copy(Header, 0, raw, 0, Header.Length);
            raw[Header.Length] = (byte)t;
            Array.Copy(payload, 0, raw, Header.Length + 1, payload.Length);
            return Convert.ToBase64String(raw);
        }

        /// <summary>解码 wtp → (tag, key, 明文 "0|IP|0", IP)。失败形态/异常返回 IP=null。</summary>
        public static (int tag, int key, string plaintext, string? ip) Decode(string b64)
        {
            byte[] raw = Convert.FromBase64String(b64);
            for (int i = 0; i < Header.Length; i++)
                if (raw[i] != Header[i]) throw new FormatException("容器头不符");

            int tag = raw[Header.Length];
            int n = raw.Length - Header.Length - 1;
            byte[] payload = new byte[n];
            Array.Copy(raw, Header.Length + 1, payload, 0, n);

            int key = payload[0] ^ 0x30;                       // 明文恒以 '0' 开头
            byte[] buf = new byte[n];
            for (int i = 0; i < n; i++) buf[i] = (byte)(payload[i] ^ key);

            // 删除 tag 处的 NUL
            string plaintext;
            if (tag >= 0 && tag < n)
            {
                byte[] pt = new byte[n - 1];
                Array.Copy(buf, 0, pt, 0, tag);
                Array.Copy(buf, tag + 1, pt, tag, n - 1 - tag);
                plaintext = Encoding.Latin1.GetString(pt);
            }
            else plaintext = Encoding.Latin1.GetString(buf);

            // 解析中段 IP ("0|IP|0")
            string? ip = null;
            if (plaintext.StartsWith("0|") && plaintext.EndsWith("|0") && plaintext.Length > 4)
            {
                string mid = plaintext.Substring(2, plaintext.Length - 4);
                var parts = mid.Split('.');
                if (parts.Length == 4) ip = mid;
            }
            return (tag, key, plaintext, ip);
        }
    }
}
