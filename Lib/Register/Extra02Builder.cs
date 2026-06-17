using System;
using System.Text;

namespace PddLib.Register
{
    /// <summary>
    /// 组装 02 报文 (POST /api/phantom/gbdbpdv/extra, data_type=1) 的明文 JSON。
    ///
    /// 与 01 不同, 02 明文是普通 JSON 对象 (非 url-encoded 表单):
    ///   - 53 字段, 严格字段序 (照样本)。
    ///   - org.json 序列化习惯: '/' 转义为 '\/' (字符串值内)。
    ///   - 字符串字段加引号; 数值/布尔/数组/对象字段不加引号 (原样 JSON)。
    ///
    /// 加密结构 (外层 body):
    ///   {"encryptInfo":"&lt;转义后的 {key,data} 包&gt;","collect_begin_time":X,"collect_end_time":Y}
    ///   {key,data} = PddBodyCrypto.EncryptPacket 输出 (AES-128-CBC + RSA), 作为 encryptInfo 字符串值时整体再 JSON 转义。
    ///
    /// 参考: device_report_example/02_extra.txt 解密结果 (53 字段) + 09_request02_extra_analysis.md。
    /// </summary>
    public static class Extra02Builder
    {
        /// <summary>
        /// 构造 02 明文 JSON 字节 (UTF-8)。
        /// </summary>
        /// <param name="d">设备指纹</param>
        /// <param name="pddid">= 01 返回的 pdd_id (body 内 pddid 与 header etag 同值)</param>
        /// <param name="currentTimeMs">currentTime: 请求时刻 ms (墙钟)</param>
        /// <param name="activeTimeMs">activeTime/upTime: 设备 uptime ms</param>
        /// <param name="processId">process_id: 进程 pid</param>
        public static byte[] BuildPlaintext(DeviceProfile d, string pddid,
            long currentTimeMs, long activeTimeMs, int processId)
        {
            var sb = new StringBuilder(20000);
            sb.Append('{');

            bool first = true;
            // 字符串字段: 加引号 + JSON 转义 ('/' → '\/')
            void S(string k, string v)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(k).Append("\":\"").Append(JsonStr(v)).Append('"');
            }
            // 原样字段: 数值/布尔/数组/对象, 不加引号也不转义
            void R(string k, string rawJson)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(k).Append("\":").Append(rawJson);
            }

            S("uid", "");
            S("app_name", "pdd");
            S("pddid", pddid);
            S("install_token", d.InstallToken);
            R("data_type", "1");
            S("app_size_info", "");
            R("version", "13");
            R("process_id", processId.ToString());
            S("platform", "android");
            S("fingerprint", d.Fingerprint);
            S("android_id", d.AndroidId);
            S("board_platform", d.BoardPlatform);
            S("flavor", "");
            S("board", d.Board);
            S("brand", d.Brand);
            S("manufactuer", d.Manufacturer);          // 拼写跟随 PDD
            S("model", d.Model);
            S("product", d.Product);
            S("device", d.Device);
            R("currentTime", currentTimeMs.ToString());
            R("activeTime", activeTimeMs.ToString());
            R("upTime", activeTimeMs.ToString());
            S("net_type", "WIFI");
            S("opertor_info", d.OpertorInfo);
            S("cert_list", d.CertList);
            S("carrier_list", "");
            S("cellinfo_list", "");
            S("market_list", d.MarketList);
            S("p29", "");
            S("p30", d.P30Apps);
            S("p72", "0");
            S("wifi_list", "");
            S("locatin", "");                          // 拼写跟随 PDD
            R("allow_mock_location", "0");
            S("is_from_mock_provider", "");
            S("running_process", d.RunningProcess);
            S("acc_server_list", d.AccServerList);
            S("lib_list", d.LibList);
            S("pm_class", d.PmClass);
            S("pm_proxy", "");
            S("display", d.Display);
            R("prop", d.Prop.ToString());
            R("cpuCore", d.CpuCore.ToString());
            S("cpuUsage", d.CpuUsage);
            R("cpuFrequency", d.CpuFrequencyJson);
            R("gyroscopeSensor", d.GyroscopeSensorJson);
            R("lightSensor", d.LightSensorJson);
            R("volume", d.VolumeJson);
            S("basebandversion1", "");
            S("basebandversion2", "");
            R("foreground", "true");
            S("p0", "1");
            S("p36", d.P36);

            sb.Append('}');
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        /// <summary>
        /// 组装 02 完整 body: 把 {key,data} 包成 encryptInfo 字符串 + collect_*time 外层。
        /// </summary>
        /// <param name="packet">PddBodyCrypto.EncryptPacket 输出的 {"key":..,"data":..}</param>
        /// <param name="collectBegin">collect_begin_time (uptime ms)</param>
        /// <param name="collectEnd">collect_end_time (uptime ms)</param>
        public static string WrapBody(string packet, long collectBegin, long collectEnd)
        {
            // encryptInfo 的值 = 整个 packet 字符串, 作为 JSON 字符串值时 '"' → '\"', '/' → '\/'
            return "{\"encryptInfo\":\"" + JsonStr(packet) + "\"," +
                   "\"collect_begin_time\":" + collectBegin + "," +
                   "\"collect_end_time\":" + collectEnd + "}";
        }

        /// <summary>
        /// org.json 风格的字符串转义: '"' → '\"', '\' → '\\', '/' → '\/',
        /// 以及常见控制字符。02 字段值里主要出现 '/' (fingerprint/路径/base64)。
        /// </summary>
        public static string JsonStr(string s)
        {
            var sb = new StringBuilder(s.Length + 16);
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '/': sb.Append("\\/"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20)
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else
                            sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }
    }
}
