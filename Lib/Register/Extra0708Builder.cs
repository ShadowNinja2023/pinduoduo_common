using System.Text;

namespace PddLib.Register
{
    /// <summary>
    /// 组装 07 (extra/data_type=15) 与 08 (extra/data_type=21) 报文明文。
    ///
    /// 两者都是 extra 格式 (单层 encryptInfo, 无 collect_*time, 同 05), 内层是普通 JSON:
    ///   07: {uid, app_name, dv, pddid, code, data_type=15, version, es, platform}
    ///   08: {version, uid, app_name, pddid, data_type=21, platform, info}
    /// 其中 es/info 是 libdyncommon 加密的检测 blob (与 03 s_f_d 同族), 无 per-台唯一 ID,
    /// 当前复刻样本基线 (Extra0708Baseline)。'/' 按 org.json 转义为 '\/'。
    /// </summary>
    public static class Extra0708Builder
    {
        /// <summary>07 明文: data_type=15, 内含 es 检测 blob。es=null 时用冻结基线(dv18);
        /// 传 Type15Builder.BuildEs 动态生成时须同时传对应 dv (18/19)。</summary>
        public static byte[] BuildPlaintext07(string pddid, string? es = null, int dv = 18)
        {
            string esVal = es ?? Extra0708Baseline.Es07;
            var sb = new StringBuilder(4096);
            sb.Append('{');
            sb.Append("\"uid\":\"\",");
            sb.Append("\"app_name\":\"pdd\",");
            sb.Append("\"dv\":").Append(dv).Append(',');
            sb.Append("\"pddid\":\"").Append(Extra02Builder.JsonStr(pddid)).Append("\",");
            sb.Append("\"code\":0,");
            sb.Append("\"data_type\":15,");
            sb.Append("\"version\":1,");
            sb.Append("\"es\":\"").Append(Extra02Builder.JsonStr(esVal)).Append("\",");
            sb.Append("\"platform\":\"android\"");
            sb.Append('}');
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        /// <summary>08 明文: data_type=21, 内含 info 证书链 blob。info=null 时用
        /// <see cref="Info08Builder"/> 动态生成 (Type21Codec 编码基线证书链); 传入 info 则原样用。</summary>
        public static byte[] BuildPlaintext08(string pddid, string? info = null)
        {
            string infoVal = info ?? Info08Builder.BuildInfo();
            var sb = new StringBuilder(16384);
            sb.Append('{');
            sb.Append("\"version\":1,");
            sb.Append("\"uid\":\"\",");
            sb.Append("\"app_name\":\"pdd\",");
            sb.Append("\"pddid\":\"").Append(Extra02Builder.JsonStr(pddid)).Append("\",");
            sb.Append("\"data_type\":21,");
            sb.Append("\"platform\":\"android\",");
            sb.Append("\"info\":\"").Append(Extra02Builder.JsonStr(infoVal)).Append("\"");
            sb.Append('}');
            return Encoding.UTF8.GetBytes(sb.ToString());
        }
    }
}
