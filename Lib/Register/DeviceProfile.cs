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
        public int AdbEnabled { get; set; } = 1;          // 样本为1; mock 建议 0
        public int DevelopmentEnabled { get; set; } = 1;  // 样本为1; mock 建议 0
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

        // ===== header 用 (从 fingerprint 派生) =====
        public string Brand { get; set; } = "Lenovo";
        public string Model { get; set; } = "TB322FC";
        public string Osv { get; set; } = "15";
        public string BuildId { get; set; } = "AQ3A.250129.001";
        public int ScreenWidth { get; set; } = 1519;
        public int ScreenHeight { get; set; } = 1871;
        public double Dpr { get; set; } = 2.75;

        /// <summary>header cookie: api_uid (服务端首访下发, 可空测试)</summary>
        public string HeaderApiUid { get; set; } = "Ck+BXWoZ7cdhwwDbr/q2Ag==";

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
