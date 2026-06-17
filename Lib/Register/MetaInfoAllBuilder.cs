using System;
using System.Collections.Generic;
using System.Text;
using static PddLib.Register.MetaInfoSubBuilder;

namespace PddLib.Register
{
    /// <summary>
    /// 04 报文 (meta_type=all) 的会话/运行时参数。
    ///
    /// 机型/环境基线字段从 <see cref="MetaInfoAllBaseline"/> 取 (线格式常量);
    /// 设备唯一性字段从 <see cref="DeviceProfile"/> 取; 本类只承载"每次请求会变 / mock 需区分"的字段。
    /// 默认值面向 mock 干净设备 (p26 空 / fk_data 干净基线 / 运行时取当前)。
    /// </summary>
    public class Meta04Options
    {
        public string Pddid { get; set; } = "";
        /// <summary>known_device: 本地已持有 pddid → 1; 全新设备首注册 → 0。</summary>
        public int KnownDevice { get; set; } = 0;

        /// <summary>body cookie (上次会话残留); mock 新设备置空; null=取 device.BodyCookie。</summary>
        public string? Cookie { get; set; } = "";

        // —— 时间戳 (运行时) ——
        public long? InstallTimeMs { get; set; }       // null=device.P46InstallTime
        public long? AppUpdateTimeMs { get; set; }     // null=InstallTime
        public long? CurrentTimeMs { get; set; }       // null=now
        public long? BootTime { get; set; }            // null=device.BootTime

        // —— 序号 / 运行时量 ——
        public int Sequence { get; set; } = 0;
        public int LocalSequence { get; set; } = 1;
        public int? ProcessId { get; set; }            // null=随机
        public int Brightness { get; set; } = 40;
        public long? AvailableMemory { get; set; }     // null=随机合理
        public long? AvailableCapacity { get; set; }   // null=device.AvailableCapacity

        // —— 设备绑定加密 (可被 mock 重算覆盖); null=用 device 当前值 ——
        public string? BatteryStatus { get; set; }     // 原文(未编码); null=device.BatteryStatus
        public string? UserEnv2 { get; set; }          // null=device.UserEnv2
        public string? P125 { get; set; }              // null=device.P125

        /// <summary>p26 = 用户 CA 证书探测 (线格式原值)。mock 干净设备=空; 复刻样本时填 MetaInfoAllBaseline.P26Sample。</summary>
        public string P26 { get; set; } = MetaInfoAllBaseline.P26Mock;

        // —— 加密大字段 (RC4+base64, 线格式; null=用 MetaInfoAllBaseline.* 样本基线) ——
        // p50/p65/p53/p68 = 应用/ROM 绑定, mock 复刻基线安全; p85 含会话时间戳, 应与 DynsoLoadTs/fk_data 联动重算。
        public string? P50 { get; set; }
        public string? P65 { get; set; }
        public string? P85 { get; set; }
        public string? P53 { get; set; }
        public string? P68 { get; set; }

        /// <summary>dynso 加载时间戳 ms: p85 与 fk_data.dynso_load_ts 共享此值 (联动)。null=各自默认。</summary>
        public long? DynsoLoadTs { get; set; }

        /// <summary>mediaDrm 线格式; null=用 MetaInfoAllBaseline.MediaDrm 样本基线。
        /// mock 应按设备 Widevine ID 重建 (见 MetaInfoAllBuilder.BuildMediaDrmWire)。</summary>
        public string? MediaDrm { get; set; }

        /// <summary>fk_data 原样 JSON; null=FkDataBuilder.BuildMock()。</summary>
        public string? FkData { get; set; }

        /// <summary>样本逐字节复刻用: 填入 04 样本的全部会话/运行时值。</summary>
        public static Meta04Options ForSample04() => new Meta04Options
        {
            Pddid = "WqfIGg5r",
            KnownDevice = 1,
            Cookie = "ZeIuI2oZ7cpqxjKiVqBBAg==",
            InstallTimeMs = 1779993900164,
            AppUpdateTimeMs = 1779993900164,
            CurrentTimeMs = 1780084170381,
            BootTime = 1779994464,
            Sequence = 0,
            LocalSequence = 72,
            ProcessId = 581,
            Brightness = 40,
            AvailableMemory = 8523988992,
            AvailableCapacity = 352956366848,
            BatteryStatus =
                "technology,Li-ion,icon-small,17303962,max_charging_voltage,5000000,health,2," +
                "max_charging_current,1500000,status,2,real_type,CDP,plugged,1,voltage_now,,present,true," +
                "android.os.extra.CHARGING_STATUS,0,seq,6489,charge_counter,6026130,level,99,scale,100," +
                "temperature,337,voltage,4232,android.os.extra.CYCLE_COUNT,57,charge_rate,1,invalid_charger,0," +
                "battery_low,false,",
            UserEnv2 =
                "416AiYYGHAkkchgVbxdqqFohpYZSFDUa27UTeAVFwGPGHs2gmcwvQ5/sMn2X7GDDKiDF3kqesAom2/wg4NW6/XAmhHk5mWsv4IjtkHQH4sdN2xpt7j/luNkLXnGK03rTuqxg48hjDYDvwoSth7zAhRgUivGvhp3nfP1UIpB6lz0JstU+rx0BqipfR/bDggje",
            P125 = "gmpnl5sH+PnHogaanpLZwY41+4xdRYk7cLJAAmyQOsiSy5hW",
            P26 = MetaInfoAllBaseline.P26Sample,
            FkData = FkDataBuilder.Build(1780084180968, "0805465284"),
        };
    }

    /// <summary>
    /// 组装 04 报文 (POST /project/meta_info, meta_type=all, scene=1) 的 plaintext。
    ///
    /// 与 01 同一接口 / 同一单层 ng() 加密 / 同一 url-encoded 表单模板, 仅 meta_type=all 全量填充字段。
    /// 137 token, 严格按样本顺序; 编码规则逐字段对齐样本 (部分 JavaUrlEncode, 部分原样 JSON/文本)。
    ///
    /// 参考: device_report_example/04_meta_info.txt 解密结果 (137 token) + 11_request04_meta_info_analysis.md。
    /// </summary>
    public static class MetaInfoAllBuilder
    {
        public static byte[] BuildPlaintext(DeviceProfile d, Meta04Options o)
        {
            long installMs = o.InstallTimeMs ?? d.P46InstallTime;
            long appUpdateMs = o.AppUpdateTimeMs ?? installMs;
            long currentMs = o.CurrentTimeMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long bootTime = o.BootTime ?? d.BootTime;
            int pid = o.ProcessId ?? Random.Shared.Next(300, 30000);
            long availMem = o.AvailableMemory ?? (d.TotalMemory / 2 + Random.Shared.Next(0, 2_000_000_000));
            long availCap = o.AvailableCapacity ?? d.AvailableCapacity;
            string cookie = o.Cookie ?? d.BodyCookie;
            string battery = o.BatteryStatus ?? d.BatteryStatus;
            string userEnv2 = o.UserEnv2 ?? d.UserEnv2;
            string p125 = o.P125 ?? d.P125;
            string fkData = o.FkData ?? FkDataBuilder.BuildMock();

            var t = new List<string>(140);
            void F(string k, string v) => t.Add($"{k}={v}");
            void Bare(string v) => t.Add(v);

            F("platform_type", "1");                                  // 0
            F("sharedpreference_id", d.SharedPreferenceId);           // 1
            F("dpi", MetaInfoAllBaseline.Dpi);                        // 2
            F("resolution", MetaInfoAllBaseline.Resolution);          // 3
            F("mac", "");                                             // 4
            F("uid", "");                                             // 5
            F("cookie", JavaUrlEncode(cookie));                       // 6
            F("android_id", d.AndroidId);                             // 7
            F("sno", d.Sno);                                          // 8
            F("cpuinfo", "");                                         // 9
            F("build_id", d.BuildId);                                 // 10
            F("fingerprint", JavaUrlEncode(d.Fingerprint));           // 11
            F("characteristics", MetaInfoAllBaseline.Characteristics);// 12
            F("battery_status", JavaUrlEncode(battery));              // 13
            F("boot_time", bootTime.ToString());                      // 14
            F("root", d.Root.ToString());                             // 15
            F("rom_status", d.RomStatus.ToString());                  // 16
            F("install_time", installMs.ToString());                  // 17
            F("app_update_time", appUpdateMs.ToString());             // 18
            F("eth_check", d.EthCheck.ToString());                    // 19
            F("p0", "17");                                            // 20
            F("p1", MetaInfoAllBaseline.P1);                          // 21
            F("p2", MetaInfoAllBaseline.P2);                          // 22
            F("p3", MetaInfoAllBaseline.P3);                          // 23
            F("p4", d.P4);                                            // 24
            F("p5", MetaInfoAllBaseline.P5);                          // 25
            F("p6", MetaInfoAllBaseline.P6);                          // 26
            F("p7", d.P7AbnormalApps);                                // 27
            F("p8", MetaInfoAllBaseline.P8);                          // 28
            F("p9", "");                                              // 29
            F("p10", d.AndroidId);                                    // 30  = android_id
            F("p11", "");                                             // 31
            F("p12", "");                                             // 32
            F("p13", MetaInfoAllBaseline.P13);                        // 33
            F("p14", "null");                                         // 34
            F("p15", "");                                             // 35
            F("p16", MetaInfoAllBaseline.P16);                        // 36
            F("p17", MetaInfoAllBaseline.P17);                        // 37
            F("p18", MetaInfoAllBaseline.P18);                        // 38
            F("p19", MetaInfoAllBaseline.P19);                        // 39
            F("p20", MetaInfoAllBaseline.P20);                        // 40
            F("p21", "");                                             // 41
            F("p22", d.P22Mac);                                       // 42
            F("p23", MetaInfoAllBaseline.P23);                        // 43
            F("p24", MetaInfoAllBaseline.P24);                        // 44
            F("p25", "");                                             // 45
            F("p26", o.P26);                                          // 46
            F("p27", "");                                             // 47
            F("p28", "");                                             // 48
            F("p31", MetaInfoAllBaseline.P31);                        // 49
            F("p32", MetaInfoAllBaseline.P32);                        // 50
            F("p33", MetaInfoAllBaseline.P33);                        // 51
            F("p34", MetaInfoAllBaseline.P34);                        // 52
            F("p35", "");                                             // 53
            F("p37", MetaInfoAllBaseline.P37);                        // 54
            F("p38", MetaInfoAllBaseline.P38);                        // 55
            F("p47", d.P47);                                          // 56
            F("p49", JavaUrlEncode(d.P49));                           // 57
            F("p50", o.P50 ?? MetaInfoAllBaseline.P50);              // 58
            F("p51", MetaInfoAllBaseline.P51);                        // 59
            F("p52", MetaInfoAllBaseline.P52);                        // 60
            F("p53", o.P53 ?? MetaInfoAllBaseline.P53);              // 61
            F("p57", MetaInfoAllBaseline.P57);                        // 62
            F("p65", o.P65 ?? MetaInfoAllBaseline.P65);              // 63
            F("p68", o.P68 ?? MetaInfoAllBaseline.P68);              // 64
            F("p80", "");                                             // 65
            F("p81", "");                                             // 66
            F("p85", o.P85 ?? MetaInfoAllBaseline.P85);              // 67
            F("p89", "");                                             // 68
            F("p90", d.P90);                                          // 69
            F("p124", "");                                            // 70
            F("p125", JavaUrlEncode(p125));                           // 71
            F("start_by_user", "true");                               // 72
            F("install_token", d.InstallToken);                      // 73
            F("app_type", "");                                        // 74
            F("app_version", d.AppVersion);                           // 75
            F("device_id", "");                                       // 76
            F("tmp_id", "");                                          // 77
            F("clipboard_md5", "");                                   // 78
            F("commitid", MetaInfoAllBaseline.Commitid);              // 79
            F("uuid", d.Uuid);                                        // 80
            F("scene", "1");                                          // 81
            F("meta_type", "all");                                    // 82
            F("p46", d.P46InstallTime.ToString());                    // 83
            F("imei_shown", MetaInfoAllBaseline.ImeiShown);           // 84
            F("instrumentation_chain", MetaInfoAllBaseline.InstrumentationChain); // 85
            F("known_device", o.KnownDevice.ToString());              // 86
            F("oaid", d.Oaid);                                        // 87
            F("version", d.Version);                                  // 88
            F("wallpaper_md5", "");                                   // 89
            F("instrumentation", d.Instrumentation);                  // 90
            F("kernelVersion", "");                                   // 91
            F("ringtone", "");                                        // 92
            F("alarm", "");                                           // 93
            F("notification", "");                                    // 94
            F("p29", "");                                             // 95
            F("p30", JavaUrlEncode(d.P30));                           // 96
            F("p72", "1");                                            // 97
            F("input_mathod", d.InputMethod);                         // 98
            F("secure_lock", d.SecureLock.ToString());                // 99
            F("ip_list", JavaUrlEncode(d.IpList));                    // 100
            F("connected_wifi", "");                                  // 101
            F("wifi", "");                                            // 102
            F("development_enabled", d.DevelopmentEnabled.ToString());// 103
            F("simState", d.SimState.ToString());                     // 104
            F("totalcapacity", d.TotalCapacity.ToString());           // 105
            F("availablecapacity", availCap.ToString());              // 106
            F("totalmemory", d.TotalMemory.ToString());               // 107
            F("psno", "");                                            // 108
            F("adb_enabled", d.AdbEnabled.ToString());                // 109
            F("sn_1", "");                                            // 110
            F("sn_2", "");                                            // 111
            F("sn_3", MetaInfoAllBaseline.Sn3);                       // 112
            F("brightness", o.Brightness.ToString());                 // 113
            F("availablememory", availMem.ToString());                // 114
            F("imei_permission", MetaInfoAllBaseline.ImeiPermission); // 115
            F("net_type", "WIFI");                                    // 116
            F("fk_result", "");                                       // 117
            F("machine_arch", MetaInfoAllBaseline.MachineArch);       // 118
            F("arp_info", "");                                        // 119
            F("user_phonename", "");                                  // 120
            F("process_id", pid.ToString());                          // 121
            F("cid_inner", "");                                       // 122
            F("cid", "");                                             // 123
            F("input_device", MetaInfoAllBaseline.InputDevice);       // 124
            F("wifi_config", "");                                     // 125
            F("target_version", MetaInfoAllBaseline.TargetVersion);   // 126
            F("user_env2", JavaUrlEncode(userEnv2));                  // 127
            F("foreground", "true");                                  // 128
            F("currentTime", currentMs.ToString());                   // 129
            F("mediaDrm", o.MediaDrm ?? MetaInfoAllBaseline.MediaDrm); // 130
            Bare("");                                                 // 131 (&& 空段)
            F("sequence", o.Sequence.ToString());                     // 132
            F("local_sequence", o.LocalSequence.ToString());          // 133
            F("did_info", JavaUrlEncode(d.DidInfo));                  // 134
            F("fk_data", fkData);                                     // 135  (原样 JSON)
            F("pddid", o.Pddid);                                      // 136

            return Encoding.UTF8.GetBytes(string.Join("&", t));
        }

        // mediaDrm 模板: 0:<widevineId>|<pkg>|<CDM版本>|<name>;  (除 widevineId 外均 ROM/CDM 版本绑定)
        private const string MediaDrmPkg = "com.google.android.widevine";
        private const string MediaDrmCdmVer = "19.0.1@AV1A.241014.001"; // ROM/CDM 版本基线
        private const string MediaDrmName = "Widevine CDM";

        /// <summary>
        /// 由 Widevine deviceUniqueId (32B/64hex) 重建 mediaDrm 线格式值。
        /// 仅 widevineId 是 per-unit 唯一; pkg/CDM版本/name 是 ROM 绑定基线, 保持不变。
        /// </summary>
        public static string BuildMediaDrmWire(string widevineIdHex)
        {
            string plain = $"0:{widevineIdHex}|{MediaDrmPkg}|{MediaDrmCdmVer}|{MediaDrmName};";
            return JavaUrlEncode(plain);
        }
    }
}
