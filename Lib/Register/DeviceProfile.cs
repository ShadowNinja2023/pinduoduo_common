using System;
using PddLib.Crypto;

namespace PddLib.Register
{
    /// <summary>
    /// 一台 mock 设备的持久化指纹与会话字段集合。
    ///
    /// 字段对应 01 报文 (meta_type=sub) 解密后的 url-encoded 表单。
    /// 大部分为 per-device 持久化值, 应由设备池下发并长期保持不变;
    /// RuntimeState 里的字段每次请求前刷新。
    ///
    /// 默认值取自 device_report_example/01_meta_info.txt (Lenovo TB322FC),
    /// 用于离线逐字节验证; 生产环境替换为设备池下发值。
    /// </summary>
    public class DeviceProfile
    {
        // ===== 设备硬唯一性 =====
        public string SharedPreferenceId { get; set; } = "b202f69912e3470a8ecd93bb3f1cd486";
        public string AndroidId { get; set; } = "5358b6fd9144e561";
        public string Uuid { get; set; } = "5543333e-9cc3-4447-beb3-76ac6f97a373";
        public string Oaid { get; set; } = "733d9aeca4b5f489717daeb21b43dea5";
        public string AppVersion { get; set; } = "8.8.0";
        public string Version { get; set; } = "205";

        // ===== 设备硬件指纹 =====
        public string Fingerprint { get; set; } =
            "Lenovo/TB322FC_PRC/TB322FC:15/AQ3A.250129.001/ZUXOS_1.1.11.202_250919_PRC:user/release-keys";
        public string Sno { get; set; } = "unknown";
        public string P22Mac { get; set; } = "26:9D:12:9B:AD:86";
        public long TotalCapacity { get; set; } = 482911531008;
        public long AvailableCapacity { get; set; } = 352980512768;
        public long TotalMemory { get; set; } = 15882305536;

        // ===== 系统状态 =====
        public long BootTime { get; set; } = 1779994465;
        public int Root { get; set; } = 0;
        public int RomStatus { get; set; } = 0;
        public int EthCheck { get; set; } = 0;
        public int SimState { get; set; } = 0;
        public int AdbEnabled { get; set; } = 0;          // mock 干净设备: adb 未开启 (adb_status=stopped/sys_usb=mtp)
        public int DevelopmentEnabled { get; set; } = 0;  // mock 干净设备: 开发者模式关
        public int SecureLock { get; set; } = 0;

        // ===== 电池 =====
        public string BatteryStatus { get; set; } =
            "technology,Li-ion,icon-small,17303962,max_charging_voltage,5000000,health,2," +
            "max_charging_current,1500000,status,2,real_type,CDP,plugged,1,voltage_now,,present,true," +
            "android.os.extra.CHARGING_STATUS,0,seq,6487,charge_counter,6026130,level,99,scale,100," +
            "temperature,337,voltage,4234,android.os.extra.CYCLE_COUNT,57,charge_rate,1,invalid_charger,0," +
            "battery_low,false,";

        // ===== 网络 =====
        public string IpList { get; set; } =
            "fe80::34ed:57ff:fe6b:f8ec%dummy0;fe80::249d:12ff:fe9b:ad86%wlan0;" +
            "fdc2:af5:5c6f:1a00:249d:12ff:fe9b:ad86;fdc2:af5:5c6f:1a00:5ee5:be72:4974:c63c;" +
            "fdc2:af5:5c6f:1a00:7e88:5b04:cb98:7946;192.168.3.31;fe80::9461:54ca:b52d:f5e6%tun0;10.0.0.2;";

        // ===== body 内 cookie (上次会话残留, 可留空测试) =====
        public string BodyCookie { get; set; } = "ZeIuHWoZ7ccmHABlbs+jAg==";

        // ===== 应用/输入 =====
        public string P7AbnormalApps { get; set; } = "com.smile.gifmaker|-8hTwwxJj2djT9rY4-mAYvw==;";
        public string InputMethod { get; set; } = "com.sohu.inputmethod.sogou.oem";
        public string Instrumentation { get; set; } = "android.app.Instrumentation";
        // ===== app 安装路径随机段 (Android10+ /data/app/~~<seg1>/<pkg>-<seg2>/, per-install) =====
        // ★ 同一对 seg 同时出现在 type15(es).p75 与 type16(proc-maps 清单) → 必须联动一致。
        /// <summary>样本基线段1 (~~ 后)。</summary>
        public const string BaselineApkSeg1 = "D4jsoNd_EmEwJ_s8Wz53nQ==";
        /// <summary>样本基线段2 (包名后)。</summary>
        public const string BaselineApkSeg2 = "BjQZUCNOcAKTo4XQtr8rVA==";
        /// <summary>app 安装目录随机段1 (~~ 后)。默认基线; mock 随机化。</summary>
        public string ApkDirSeg1 { get; set; } = BaselineApkSeg1;
        /// <summary>app 安装目录随机段2 (包名后)。默认基线; mock 随机化。</summary>
        public string ApkDirSeg2 { get; set; } = BaselineApkSeg2;
        /// <summary>type15(es).p75: app base.apk 全路径 (由两段拼出, 与 type16 maps 清单联动一致)。长度须 ≤ p75 keystream(117B)。</summary>
        public string ApkPath => $"/data/app/~~{ApkDirSeg1}/com.xunmeng.pinduoduo-{ApkDirSeg2}/base.apk";

        // ===== 加密预算字段 (算法未还原, 先复刻样本固定值) =====
        public string P49 { get; set; } =
            "iBio4vwBEchUN3vEdQc1S0GRVrV3gpH6E6hFvGc5PhgJLWHDeDIAMPOsyoD6NDQ7PXcXNHBbTVft/mEOZp8OOVV0r9hlKz//n3iqDOlNhK2LSKJRQdZQpCBHrHmfhqE9423s2ruglQ/9jhCVx87/u763pyZa5kjNoIjxDVG9JcGsX+Z/28klzbhvzrhm3BfVlETD9wHsb60bxXsk+PPwuvuU7KR2oEcnwEuFo1cZOe4EirgLiN+hSKXBaI3pm3b4RNp4mh2OVfNx0e7Tsy5rHgvzV2u+1r0rb8i+dkgw0vqZhhIeSPtXgoBWPHnGd+lgMI7DSXza2BQ+KbFKsXbuC/5W3I9mcIWh7GAp1m4tOnwM0X0tcorEMKWtVo/O9BmaBNYQvj7iDdyHpRjXfB5EWh2Ofg==";
        public string P30 { get; set; } = "OT70o9b7xtqXkanvAW7PJm4E5+NkmuGn6y0Ym7k3cAg42lZQ";
        public string P125 { get; set; } = "g2xjwcUH/6bHrFfMzJLZwI86+40GRNk7ceQSAmjCNcLFnsxW";
        public string UserEnv2 { get; set; } =
            "fKngCeNhzVcydUeyFLBk3BSFNjN9bh8bwfE+QgRqp68/DG+ZDINxieLbDmIF9oN2Wdv4E4OP12mygtxWnG+c+VtZk1mZTArGDyx1dt/Df/Qy4V/UML6sI4T8PCK4azd2";

        // ===== 时间戳 (per-install 持久化) =====
        public long P46InstallTime { get; set; } = 1779712666437;
        public string P90 { get; set; } = "2025-07-31 19:43:46.507999992 +0800";

        // ===== p4: uname (JSON) =====
        public string P4 { get; set; } =
            "{\"2\":\"Linux+localhost+6.6.89-android15-8-g14220ae4ce65-ab13680582-4k+%231+SMP+PREEMPT+Mon+Jun+23+07%3A30%3A57+UTC+2025+aarch64+Toybox\"}";

        // ===== did_info (per-device 持久化整串, 原始形态; Builder 做 JavaUrlEncode) =====
        public string DidInfo { get; set; } =
            "1970-01-08 07:39:40.359999986 +0800;2025-07-31 19:43:46.371999992 +0800;" +
            "0000000000000000;9b14a735a1062b3f;117898323;11880957;2025681;4960;" +
            "ddc177d2-dd0d-4bdf-bd6e-4928956e05c6;1970-01-08 07:39:41.235999986 +0800;";

        // ===== 会话凭据 =====
        /// <summary>p47: 会话 UUID, 先于 pddid 存在 (本地生成/持久化), 同时是 x-p1 明文头与 RC4 key 来源</summary>
        public string P47 { get; set; } = "S5n3Bd6L-ofNf-Zv3q-402e-4yHlPVhy5foo";

        // ===== 日志流 user_trace/sensor 用的设备身份 (真机 te.gif/t.gif 上报, 服务端疑与注册指纹交叉核对) =====
        /// <summary>本次开机的 boot_id (UUID)。每次真机重启变化, mock 一次会话内固定。</summary>
        public string BootId { get; set; } = "e5dcaec3-ce45-4a00-a0be-30f1e39b7237";
        /// <summary>机型营销名 (ro.config.marketing_name 等), user_trace.model_name。默认 Lenovo Y700。</summary>
        public string ModelName { get; set; } = "拯救者平板 Y700";
        /// <summary>ROM 版本 (ro.build.display.id 类), user_trace.rom_version / rom_build_id (真机两者同值)。</summary>
        public string RomVersion { get; set; } = "TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.202_ST_250919";
        /// <summary>titan 安装 id (UUID), install/user_trace 事件共用。</summary>
        public string TitanInstallId { get; set; } = "2c16b3ef-de93-477f-9d22-c949bdb3cb40";

        // ===== header 用 (从 fingerprint 派生) =====
        public string Brand { get; set; } = "Lenovo";
        public string Model { get; set; } = "TB322FC";
        public string Osv { get; set; } = "15";
        public string BuildId { get; set; } = "AQ3A.250129.001";
        public int ScreenWidth { get; set; } = 1519;
        public int ScreenHeight { get; set; } = 1871;
        public double Dpr { get; set; } = 2.75;

        // ===== 04/06 (meta_type=all) 机型字段 (默认=Lenovo 基线, 与 MetaInfoAllBaseline 对齐; 转换器按机型覆盖) =====
        /// <summary>04 dpi (densityDpi)。默认 440 (Lenovo)。</summary>
        public int Dpi { get; set; } = 440;
        /// <summary>04 resolution: 真实分辨率 "WxH"。</summary>
        public string ResolutionReal { get; set; } = "1520x1904";
        /// <summary>04 p57: 可用显示区 "W*H"。</summary>
        public string ResolutionUsable { get; set; } = "1519*1871";
        /// <summary>04 characteristics: Build.CHARACTERISTICS (tablet / 空)。</summary>
        public string Characteristics { get; set; } = "tablet";
        /// <summary>04 p18: 时区 "Asia/Shanghai GMT+08:00"。</summary>
        public string TimeZone { get; set; } = "Asia/Shanghai GMT+08:00";
        /// <summary>04 p20: SoC 型号 (如 SM8750P / MT6989)。</summary>
        public string Soc { get; set; } = "SM8750P";
        /// <summary>04 p8: 系统启动次数 (boot_count)。默认 41 (Lenovo)。</summary>
        public int BootCount { get; set; } = 41;
        /// <summary>04 p19: 电池容量 mAh (PowerProfile.getBatteryCapacity)。默认 7500; 输出为 "{v}.0"。</summary>
        public int BatteryCapacityMah { get; set; } = 7500;
        /// <summary>04 p51: 铃声 URI (原文, 未 URLEncode)。</summary>
        public string RingtoneUri { get; set; } = "content://media/internal/audio/media/106?title=StereoTime&canonical=1";
        /// <summary>04 p52: 通知音 URI (原文, 未 URLEncode)。</summary>
        public string NotificationUri { get; set; } = "content://media/internal/audio/media/17?title=EtherealMallets&canonical=1";
        /// <summary>04 p2: KeyStore attestation (线格式, url-encoded)。默认=样本基线; mock 随机化 verifiedBootKey/Hash。</summary>
        public string P2 { get; set; } = MetaInfoAllBaseline.P2;

        /// <summary>header cookie: api_uid (服务端首访下发, 可空测试)</summary>
        public string HeaderApiUid { get; set; } = "Ck+BXWoZ7cdhwwDbr/q2Ag==";

        /// <summary>
        /// anti_content nano_fp (= tag16 nano_cookie_fp = tag17 nano_storage_fp)。
        /// H5 前端持久随机 ID (存 cookie+localStorage 的 _nano_fp), per-device 稳定。
        /// 空 → GetAntiContentAsync 首次调用时懒生成 (AntiContentCodec.GenNanoFp) 并回填, 随存档持久。
        /// </summary>
        public string NanoFp { get; set; } = "";

        // ===== info2 (2af anti-token) 专用字段 (登录类接口) =====
        /// <summary>SDK_INT (Build.VERSION.SDK_INT)。安卓15=35。</summary>
        public int SdkInt { get; set; } = 35;
        /// <summary>ro.build.date.utc (系统构建日期, 秒)。</summary>
        public long BuildDateUtc { get; set; } = 1759081533;
        /// <summary>/system/build.prop 修改/创建时间 (秒)。</summary>
        public long BuildPropTimeUtc { get; set; } = 1230768000;
        /// <summary>TelephonyManager.getSimOperatorName()。无 SIM 空。</summary>
        public string SimOperatorName { get; set; } = "";
        /// <summary>TelephonyManager.getSimCountryIso()。无 SIM 空; 有 SIM 可写死 "cn"。</summary>
        public string SimCountryIso { get; set; } = "";
        /// <summary>TelephonyManager.getNetworkType() 文本 (如 "LTE")。无网 "UNKNOWN"。</summary>
        public string NetworkType { get; set; } = "UNKNOWN";
        /// <summary>getNetworkOperator() 前 3 位 (MCC, 如 "460")。无 SIM 空。</summary>
        public string NetworkMcc { get; set; } = "";
        /// <summary>getNetworkOperator() 后 2~3 位 (MNC, 如 "11")。无 SIM 空。</summary>
        public string NetworkMnc { get; set; } = "";
        /// <summary>getNetworkOperatorName() (如 "CHN-CT")。无 SIM 空。</summary>
        public string NetworkOperatorName { get; set; } = "";
        /// <summary>getNetworkCountryIso()。无网空; 有网可写死 "cn"。</summary>
        public string NetworkCountryIso { get; set; } = "";
        /// <summary>TelephonyManager.getDataState() 数字值。</summary>
        public int DataState { get; set; } = 0;
        /// <summary>TelephonyManager.getDataActivity() 数字值。</summary>
        public int DataActivity { get; set; } = 0;
        /// <summary>info2 idx=0x1d kernel /proc/version 复合 value (原始字节, 机型级基线)。</summary>
        public byte[] Info2KernelValue { get; set; } = PddLib.Crypto.Info2Baseline.KernelValue;

        // ===== 04 报文 (meta_type=all) 专用 =====
        /// <summary>mediaDrm 的 Widevine deviceUniqueId (32B/64hex), 每台物理设备唯一 → mock 必随机。</summary>
        public string MediaDrmWidevineId { get; set; } =
            "b4c70928139f4ff7ccec3f412ff221cb7f72d229598549fa5731be0c023b9bdc";

        // ===== 02 报文 (extra/data_type=1) 专用字段 =====
        // A 类唯一性: install_token (per-install UUID)。默认取样本值, mock 时 NewDevice 重置。
        public string InstallToken { get; set; } = "e5609738-2aa3-4243-ba1f-c93312391b57";

        // D 类机型/环境基线 (默认取样本; 同型号设备一致, 保持真实)
        public string BoardPlatform { get; set; } = Extra02Baseline.BoardPlatform;
        public string Board { get; set; } = Extra02Baseline.Board;
        public string Manufacturer { get; set; } = Extra02Baseline.Manufacturer;
        public string Product { get; set; } = Extra02Baseline.Product;
        public string Device { get; set; } = Extra02Baseline.Device;
        public string OpertorInfo { get; set; } = Extra02Baseline.OpertorInfo;
        public string CertList { get; set; } = Extra02Baseline.CertList;
        public string MarketList { get; set; } = Extra02Baseline.MarketList;
        public string RunningProcess { get; set; } = Extra02Baseline.RunningProcess;
        public string AccServerList { get; set; } = Extra02Baseline.AccServerList;
        public string LibList { get; set; } = Extra02Baseline.LibList;
        public string PmClass { get; set; } = Extra02Baseline.PmClass;
        public string Display { get; set; } = Extra02Baseline.Display;
        public long Prop { get; set; } = Extra02Baseline.Prop;
        public int CpuCore { get; set; } = (int)Extra02Baseline.CpuCore;
        public string CpuUsage { get; set; } = Extra02Baseline.CpuUsage;
        public string CpuFrequencyJson { get; set; } = Extra02Baseline.CpuFrequencyJson;
        public string GyroscopeSensorJson { get; set; } = Extra02Baseline.GyroscopeSensorJson;
        public string LightSensorJson { get; set; } = Extra02Baseline.LightSensorJson;
        public string VolumeJson { get; set; } = Extra02Baseline.VolumeJson;
        public string P36 { get; set; } = Extra02Baseline.P36;

        // p30 (02): 已安装应用全清单 base64 基线 (方案A 复刻样本, 同 ROM 预装集一致)
        public string P30Apps { get; set; } = Extra02Baseline.P30Apps;

        /// <summary>
        /// 是否为 mock 设备 (DeviceMocker 产出)。
        /// 为 true 时 RegisterClient 发送前会用请求时刻 ts 重算 user_env2 (它含 android_id)。
        /// FromSample01 默认 false, 保证逐字节复刻样本的离线验证不受影响。
        /// </summary>
        public bool IsMock { get; set; } = false;

        /// <summary>user_env2 明文 schema 形态 (随报文不同)。</summary>
        public enum UserEnv2Form { Min, Report01, Report04 }

        /// <summary>
        /// 用当前 android_id + 给定毫秒时间戳重算 user_env2 (TEA-CBC, 含 android_id)。
        /// mock 设备改了 android_id 后必须重算, 否则 user_env2 仍含旧 android_id → 服务端可发现矛盾。
        ///
        /// ★ user_env2 明文是可变 schema (见 UserEnv2Codec): 01=含"4"形态; 04=an/pk/extra 形态。
        /// 默认 Report01 (01 是 mock 主链路首包)。06 长形态 (含 8/extra 容器) 由 06 builder 单独构造。
        /// </summary>
        public void RecomputeUserEnv2(long tsMs, int seq = 0, UserEnv2Form form = UserEnv2Form.Report01)
        {
            var f = form switch
            {
                UserEnv2Form.Report04 => UserEnv2Codec.Form04(AndroidId, tsMs, seq),
                UserEnv2Form.Min => UserEnv2Codec.FormMin(AndroidId, tsMs, seq),
                _ => UserEnv2Codec.Form01(AndroidId, tsMs, seq),
            };
            UserEnv2 = UserEnv2Codec.GenerateFrom(f);
        }

        /// <summary>构造一个与 01 样本完全一致的设备 (默认值即样本值)</summary>
        public static DeviceProfile FromSample01() => new DeviceProfile();
    }
}
