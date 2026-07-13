using System.Text;
using PddLib.Crypto;

namespace PddLib.Register
{
    /// <summary>
    /// 组装 data_type=16 报文 (proc-maps 上报) 的明文 JSON。
    ///
    /// 明文 (严格字段序, 逐字节复刻样本, code/r 在最前):
    /// <code>
    /// {"code":0,"r":"&lt;base64&gt;","version":1,"uid":"","app_name":"pdd",
    ///  "pddid":"&lt;01下发&gt;","data_type":"16","platform":"android"}
    /// </code>
    /// ★ 陷阱: <c>code</c>/<c>version</c> 是整数 (无引号), <c>data_type</c> 是字符串 "16" (带引号);
    ///   <c>r</c> 里的 '/' 按 org.json 习惯转义为 '\/' (复用 Extra02Builder.JsonStr)。
    ///
    /// r = <see cref="Type16Codec.Encode"/>(maps 路径清单)。默认用 <see cref="Type16Baseline.MapsRegions"/>。
    /// 外层信封与 03/05 同 (单层 encryptInfo, 种子 keygen AES), 由 RegisterClient 统一封装。
    /// </summary>
    public static class Type16Builder
    {
        /// <summary>
        /// 构造 data_type=16 明文 JSON 字节 (UTF-8)。
        /// </summary>
        /// <param name="pddid">= 01 返回的 pdd_id</param>
        /// <param name="mapsRegions">maps 路径清单明文 (';' 分隔); null 用干净基线</param>
        public static byte[] BuildPlaintext(string pddid, string? mapsRegions = null)
        {
            string r = Type16Codec.Encode(mapsRegions ?? Type16Baseline.MapsRegions);

            var sb = new StringBuilder(r.Length + 128);
            sb.Append('{');
            sb.Append("\"code\":0,");                                       // 整数, 无引号
            sb.Append("\"r\":\"").Append(Extra02Builder.JsonStr(r)).Append("\",");
            sb.Append("\"version\":1,");                                    // 整数, 无引号
            sb.Append("\"uid\":\"\",");
            sb.Append("\"app_name\":\"pdd\",");
            sb.Append("\"pddid\":\"").Append(Extra02Builder.JsonStr(pddid)).Append("\",");
            sb.Append("\"data_type\":\"16\",");                             // ★ 字符串, 带引号
            sb.Append("\"platform\":\"android\"");
            sb.Append('}');
            return Encoding.UTF8.GetBytes(sb.ToString());
        }
    }
}
