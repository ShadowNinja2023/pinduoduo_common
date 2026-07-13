using System;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// data_type=16 报文 r 字段编解码器 (libpdd_secure proc-maps 上报的离线复刻)。
    ///
    /// r = 上报进程 <c>/proc/self/maps</c> 的「pathname 列」(区域名/路径), 用 ';' 连接后整体编码。
    /// 服务端据此清单检测注入的 .so / 异常匿名映射 (frida gadget / substrate / xposed 等)。
    ///
    /// 编码 (trace + 样本全验证, 见 docs 17):
    /// <code>
    ///   明文 = "region0;region1;...;regionN;"   (';' 分隔的 maps 路径清单)
    ///   r    = base64( 明文每字节 XOR 0x4A )
    /// </code>
    /// 就是单字节 XOR 0x4A + base64, 对称可逆, 无 key 派生/无随机。
    ///
    /// 编码函数在 so 里是 OLLVM 平坦化的 (br x10 派发 + 大常量 eor 混淆),
    /// 去混淆后本质即「逐行抽 pathname → ';' 拼接 → XOR 0x4A → base64」。
    /// </summary>
    public static class Type16Codec
    {
        /// <summary>单字节 XOR 密钥 (恒定)。</summary>
        public const byte XorKey = 0x4A;

        /// <summary>编码: maps 路径清单明文 → r 字段 (base64)。</summary>
        public static string Encode(string plaintext)
        {
            byte[] pt = Encoding.UTF8.GetBytes(plaintext);
            byte[] raw = new byte[pt.Length];
            for (int i = 0; i < pt.Length; i++) raw[i] = (byte)(pt[i] ^ XorKey);
            return Convert.ToBase64String(raw);
        }

        /// <summary>解码: r 字段 (base64) → maps 路径清单明文。</summary>
        public static string Decode(string r)
        {
            byte[] raw = Convert.FromBase64String(r);
            byte[] pt = new byte[raw.Length];
            for (int i = 0; i < raw.Length; i++) pt[i] = (byte)(raw[i] ^ XorKey);
            return Encoding.UTF8.GetString(pt);
        }
    }
}
