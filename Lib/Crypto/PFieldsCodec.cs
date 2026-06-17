using System;
using System.Collections.Generic;
using System.Text;
using PddLib.Register;

namespace PddLib.Crypto
{
    /// <summary>
    /// 04 报文 (meta_type=all) 加密大字段 p50/p65/p85/p53/p68 的 codec。
    ///
    /// 全部 = JavaUrlEncode( Base64_std( RC4_standard( 明文, 各自独立16字节硬编码key ) ) ),
    /// 与 p49/p125/p30 同一 RC4+base64 函数 (libpdd_secure.so sub_18DAF4)。
    /// key 由 Frida hook (scripts/hook_ng2_pfields.js) 实测取得, 明文语义见 11_request04 第四节。
    ///
    /// 明文语义 (04 样本):
    ///   p50 = 应用 versionCode + 安装/更新时间ms 定位式 CSV (ROM/应用集+时间绑定)
    ///   p65 = 已安装输入法清单 (包名|组件)
    ///   p85 = "dynso_load_ts,c1,c2,hexid;"  (时间戳与 fk_data.dynso_load_ts 联动 + 5字节随机 id)
    ///   p53 = 小数值 (样本=45)
    ///   p68 = 空 JSON 数组 (样本=[])
    ///
    /// 关键: 五个字段均不含 android_id/oaid 等设备唯一 ID → 与随机化的唯一性字段无交叉校验,
    /// mock 复刻基线安全; p85 含会话时间戳, 应随设备/会话重算 (与 fk_data 一致)。
    /// </summary>
    public static class PFieldsCodec
    {
        /// <summary>各字段独立 RC4 key (ASCII 16B), hook 实测。</summary>
        public static readonly IReadOnlyDictionary<string, byte[]> Keys = new Dictionary<string, byte[]>
        {
            ["p50"] = Encoding.ASCII.GetBytes("a7uWyrG5cZe4eK4b"),
            ["p65"] = Encoding.ASCII.GetBytes("b62qYnx5sOc2wb5c"),
            ["p85"] = Encoding.ASCII.GetBytes("d50aNwo9vLi5jq7r"),
            ["p53"] = Encoding.ASCII.GetBytes("a7eTYRg4dWh9jP5c"),
            ["p68"] = Encoding.ASCII.GetBytes("a10Qu4y3y6d3r624"),
        };

        /// <summary>明文 → 标准 base64 (RC4 + base64, 未做 url 编码)。</summary>
        public static string EncodeBase64(string field, string plaintext)
        {
            byte[] ct = P30Codec.Rc4(Keys[field], Encoding.UTF8.GetBytes(plaintext));
            return Convert.ToBase64String(ct);
        }

        /// <summary>明文 → 线格式 (base64 再 JavaUrlEncode), 可直接作为表单字段值。</summary>
        public static string EncodeWire(string field, string plaintext)
            => MetaInfoSubBuilder.JavaUrlEncode(EncodeBase64(field, plaintext));

        /// <summary>标准 base64 → 明文 (RC4 对称解密)。</summary>
        public static string DecodeBase64(string field, string base64)
        {
            string padded = base64;
            int mod = padded.Length % 4;
            if (mod != 0) padded += new string('=', 4 - mod);
            byte[] pt = P30Codec.Rc4(Keys[field], Convert.FromBase64String(padded));
            return Encoding.UTF8.GetString(pt);
        }

        /// <summary>线格式 (JavaUrlEncode 后的 base64) → 明文。</summary>
        public static string DecodeWire(string field, string wire)
            => DecodeBase64(field, System.Net.WebUtility.UrlDecode(wire));

        /// <summary>
        /// 重建 p85 明文: "dynso_load_ts,c1,c2,hexid;"。
        /// dynsoLoadTs 应与 fk_data.dynso_load_ts 一致; hexId = 5 字节随机 (10 hex)。
        /// c1/c2 沿用样本基线 (语义未定, 干净基线值)。
        /// </summary>
        public static string BuildP85Plain(long dynsoLoadTs, string hexId10, int c1 = 23, int c2 = 67)
            => $"{dynsoLoadTs},{c1},{c2},{hexId10};";
    }
}
