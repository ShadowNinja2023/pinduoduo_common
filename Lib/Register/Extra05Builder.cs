using System.Text;

namespace PddLib.Register
{
    /// <summary>
    /// 组装 05 报文 (POST /api/phantom/gbdbpdv/extra, data_type=17) 的明文 JSON。
    ///
    /// 05 是极短的轻量上报: 6 个固定头字段 + <c>wtp</c> (= strc.pinduoduo.com 解析 IP 的编码)。
    ///
    /// 明文 (严格字段序, 逐字节复刻样本):
    /// <code>
    /// {"version":1,"uid":"","app_name":"pdd","pddid":"&lt;01下发&gt;",
    ///  "data_type":"17","platform":"android","wtp":"&lt;base64&gt;"}
    /// </code>
    /// ★ 陷阱: <c>version</c> 是整数 1 (无引号), 但 <c>data_type</c> 是字符串 "17" (带引号);
    ///   <c>wtp</c> 里的 '/' 按 org.json 习惯转义为 '\/' (复用 Extra02Builder.JsonStr)。
    ///
    /// 加密结构 (单层, 比 02 更简): body = <c>{"encryptInfo":"&lt;转义后的{key,data}包&gt;"}</c>
    ///   ★ 注意: 05 外层**没有** 02/03 的 collect_begin_time / collect_end_time。
    ///
    /// 参考: device_report_example/05_extra.txt + docs 12_request05_extra_analysis.md。
    /// </summary>
    public static class Extra05Builder
    {
        /// <summary>原 05 样本的 wtp (失败形态, 无 IP; 仅用于逐字节复刻样本, 勿用于 mock)。</summary>
        public const string SampleWtp = "D8EAAAQEAAHqx/a7u/c=";

        /// <summary>
        /// 构造 05 明文 JSON 字节 (UTF-8)。
        /// </summary>
        /// <param name="pddid">= 01 返回的 pdd_id (同 header etag)</param>
        /// <param name="wtpBase64">wtp 字段值 (base64, 未转义; '/' 会在此自动转义)</param>
        public static byte[] BuildPlaintext(string pddid, string wtpBase64)
        {
            var sb = new StringBuilder(256);
            sb.Append('{');
            sb.Append("\"version\":1,");                                   // 整数, 无引号
            sb.Append("\"uid\":\"\",");
            sb.Append("\"app_name\":\"pdd\",");
            sb.Append("\"pddid\":\"").Append(Extra02Builder.JsonStr(pddid)).Append("\",");
            sb.Append("\"data_type\":\"17\",");                            // ★ 字符串, 带引号
            sb.Append("\"platform\":\"android\",");
            sb.Append("\"wtp\":\"").Append(Extra02Builder.JsonStr(wtpBase64)).Append('"');
            sb.Append('}');
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        /// <summary>
        /// 组装 05 完整 body: 仅把 {key,data} 包成 encryptInfo 字符串 (无 collect_*time)。
        /// </summary>
        /// <param name="packet">PddBodyCrypto.EncryptPacket 输出的 {"key":..,"data":..}</param>
        public static string WrapBody(string packet)
            => "{\"encryptInfo\":\"" + Extra02Builder.JsonStr(packet) + "\"}";
    }
}
