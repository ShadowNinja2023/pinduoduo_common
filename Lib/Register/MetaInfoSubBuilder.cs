using System;
using System.Collections.Generic;
using System.Text;

namespace PddLib.Register
{
    /// <summary>
    /// 组装 01 报文 (POST /project/meta_info, meta_type=sub, scene=1) 的 plaintext。
    ///
    /// plaintext = 108 个 token 用 '&' 拼接, 其中:
    ///   - 普通字段: "key=value"
    ///   - 裸占位: "null" / "" (PDD SDK 空字段序列化习惯, 必须照样输出)
    ///
    /// 字段值采用"最终线格式"(已做 Java URLEncoder 的字段直接存编码后值),
    /// Builder 只负责按精确顺序拼接, 以保证与抓包逐字节一致。
    ///
    /// 参考: device_report_example/01_meta_info.txt 解密结果 (108 token)。
    /// </summary>
    public static class MetaInfoSubBuilder
    {
        /// <summary>
        /// 构造 01 报文 plaintext (url-encoded 表单字节)。
        /// </summary>
        /// <param name="d">设备指纹</param>
        /// <param name="pddid">pddid; 注册首包应为空</param>
        public static byte[] BuildPlaintext(DeviceProfile d, string pddid = "")
        {
            var t = new List<string>(120);

            void F(string k, string v) => t.Add($"{k}={v}");
            void Bare(string v) => t.Add(v);

            // —— 严格按样本 108 token 顺序 ——
            F("platform_type", "1");                              // 0
            F("sharedpreference_id", d.SharedPreferenceId);       // 1
            Bare("null");                                         // 2
            Bare("null");                                         // 3
            F("mac", "");                                         // 4
            F("uid", "");                                         // 5
            F("cookie", JavaUrlEncode(d.BodyCookie));             // 6
            F("android_id", d.AndroidId);                         // 7
            F("sno", d.Sno);                                      // 8
            F("cpuinfo", "");                                     // 9
            F("build_id", "");                                    // 10  (sub 模式样本为空)
            F("fingerprint", JavaUrlEncode(d.Fingerprint));       // 11
            F("characteristics", "");                             // 12
            F("battery_status", JavaUrlEncode(d.BatteryStatus));  // 13
            F("boot_time", d.BootTime.ToString());                // 14
            F("root", d.Root.ToString());                         // 15
            F("rom_status", d.RomStatus.ToString());              // 16
            Bare("null");                                         // 17
            Bare("null");                                         // 18
            F("eth_check", d.EthCheck.ToString());                // 19
            F("p0", "17");                                        // 20
            F("p1", "");                                          // 21
            F("p2", "");                                          // 22
            F("p3", "");                                          // 23
            F("p4", d.P4);                                        // 24  (原始, 仅空格→+)
            F("p5", "");                                          // 25
            F("p6", "");                                          // 26
            F("p7", d.P7AbnormalApps);                            // 27
            F("p8", "");                                          // 28
            F("p9", "");                                          // 29
            F("p10", "");                                         // 30
            F("p11", "");                                         // 31
            F("p12", "");                                         // 32
            F("p13", "");                                         // 33
            F("p14", "null");                                     // 34  (字面值 null)
            F("p15", "");                                         // 35
            F("p16", "");                                         // 36
            F("p17", "");                                         // 37
            F("p18", "");                                         // 38
            F("p19", "");                                         // 39
            F("p20", "");                                         // 40
            F("p21", "");                                         // 41
            F("p22", d.P22Mac);                                   // 42
            F("p23", "");                                         // 43
            F("p24", "");                                         // 44
            F("p25", "");                                         // 45
            F("p26", MetaInfoAllBaseline.P26Mock);                // 46 干净设备非抓包基准 "[]"
            F("p27", "");                                         // 47
            F("p28", "");                                         // 48
            F("p31", "");                                         // 49
            F("p32", "");                                         // 50
            F("p33", "");                                         // 51
            F("p34", "");                                         // 52
            F("p35", "");                                         // 53
            F("p37", "");                                         // 54
            F("p38", "");                                         // 55
            F("p47", d.P47);                                      // 56
            F("p49", JavaUrlEncode(d.P49));                       // 57
            F("p50", "");                                         // 58
            F("p51", "");                                         // 59
            F("p52", "");                                         // 60
            F("p53", "");                                         // 61
            F("p57", "");                                         // 62
            F("p65", "");                                         // 63
            F("p68", "");                                         // 64
            F("p80", "");                                         // 65
            F("p81", "");                                         // 66
            F("p85", "");                                         // 67
            F("p89", "");                                         // 68
            F("p90", d.P90);                                      // 69  (原始, 含空格)
            F("p124", "");                                        // 70
            F("p125", JavaUrlEncode(d.P125));                     // 71
            F("meta_type", "sub");                                // 72
            F("p46", d.P46InstallTime.ToString());                // 73
            F("app_version", d.AppVersion);                       // 74
            F("uuid", d.Uuid);                                    // 75
            F("oaid", d.Oaid);                                    // 76
            F("scene", "1");                                      // 77
            F("version", d.Version);                              // 78
            F("wallpaper_md5", "");                               // 79
            F("instrumentation", d.Instrumentation);              // 80
            F("kernelVersion", "");                               // 81
            F("ringtone", "");                                    // 82
            F("alarm", "");                                       // 83
            F("notification", "");                                // 84
            F("p29", "");                                         // 85
            F("p30", JavaUrlEncode(d.P30));                       // 86
            F("p72", "0");                                        // 87
            F("input_mathod", d.InputMethod);                     // 88  (拼写跟随 PDD)
            F("secure_lock", d.SecureLock.ToString());            // 89
            F("ip_list", JavaUrlEncode(d.IpList));                // 90
            F("connected_wifi", "");                              // 91
            F("wifi", "");                                        // 92
            F("development_enabled", d.DevelopmentEnabled.ToString()); // 93
            F("simState", d.SimState.ToString());                 // 94
            F("totalcapacity", d.TotalCapacity.ToString());       // 95
            F("availablecapacity", d.AvailableCapacity.ToString());// 96
            F("totalmemory", d.TotalMemory.ToString());           // 97
            F("psno", "");                                        // 98
            F("adb_enabled", d.AdbEnabled.ToString());            // 99
            F("user_env2", JavaUrlEncode(d.UserEnv2));            // 100
            F("mediaDrm", "def");                                 // 101 (sub 模式占位)
            Bare("");                                             // 102 (空段 &&)
            Bare("null");                                         // 103
            Bare("null");                                         // 104
            F("did_info", JavaUrlEncode(d.DidInfo));              // 105
            Bare("null");                                         // 106
            F("pddid", pddid);                                    // 107

            string form = string.Join("&", t);
            return Encoding.UTF8.GetBytes(form);
        }

        /// <summary>
        /// Java URLEncoder.encode(s, "UTF-8") 等价实现:
        /// 空格 → '+', 字母数字与 - _ . * 不变, 其余 → %XX (大写)。
        /// </summary>
        public static string JavaUrlEncode(string s)
        {
            var sb = new StringBuilder(s.Length * 2);
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            foreach (byte b in bytes)
            {
                char c = (char)b;
                if (c == ' ')
                    sb.Append('+');
                else if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                         (c >= '0' && c <= '9') ||
                         c == '-' || c == '_' || c == '.' || c == '*')
                    sb.Append(c);
                else
                    sb.Append('%').Append(b.ToString("X2"));
            }
            return sb.ToString();
        }
    }
}
