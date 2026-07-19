using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using PddLib.Crypto;

namespace PddLib.Register
{
    /// <summary>
    /// 设备唯一性 Mocker —— 在保持"机型类真实指纹"(Lenovo TB322FC) 不变的前提下,
    /// 只随机化"设备唯一性"字段, 使服务端把每次请求当作新设备并下发新 pdd_id。
    ///
    /// 字段分类 (详见 docs/04_device_register/NEXT_SESSION.md):
    ///   A. 必须随机化 (硬唯一标识): android_id / oaid / uuid / sharedpreference_id / p22 MAC / p47
    ///   B. 关联派生   (建议随机化): did_info / p46(install_time) / p90 / boot_time / cookie(置空)
    ///   C. 设备绑定加密 (用新值重算): user_env2 (含 android_id, 重算) / p30 (干净设备=空列表)
    ///   D. 保持不变   (机型指纹): fingerprint / p4 / build_id / 分辨率 / model/brand/osv / p49 / p125 ...
    ///
    /// user_env2 含请求时刻 ts, NewDevice 仅算一次基线; 实际发送时 RegisterClient 会用
    /// 请求 stMs 重算 (IsMock=true)。
    /// </summary>
    public static class DeviceMocker
    {
        /// <summary>
        /// 产出一台全新 mock 设备: 以 01 样本机型为基线, 随机化全部唯一性字段。
        /// </summary>
        public static DeviceProfile NewDevice()
        {
            var d = DeviceProfile.FromSample01();
            Randomize(d);
            return d;
        }

        /// <summary>
        /// 从一台真实淘宝设备记录产出一台"同品牌机型的全新 mock 设备":
        ///   转换器 (<see cref="TaobaoToPddConverter"/>) 先出机型基准 (fingerprint/brand/model/screen/... 真机值),
        ///   再随机化唯一性字段 (android_id/oaid/uuid/MAC/p47/... 全新), 保留机型指纹。
        /// </summary>
        /// <param name="record">RepedCrypto 解出的检测项集合</param>
        /// <param name="report">转换报告 (哪些字段映射/保留基线/缺失)</param>
        public static DeviceProfile NewDeviceFromTaobao(TaobaoDeviceRecord record, out ConversionReport report)
        {
            var (d, rep) = TaobaoToPddConverter.Convert(record);
            report = rep;
            Randomize(d);   // 保留 D 类机型指纹, 随机化 A/B/C 类唯一值
            return d;
        }

        // ============================================================
        // 最小 mock (minimal change) —— 以真实干净基线为底, 只改硬唯一标识
        // ============================================================

        /// <summary>
        /// 产出一台<b>最小 mock</b> 设备: 以 <see cref="DeviceProfile.FromSample01"/> (真实干净的
        /// Lenovo TB322FC 基线, 与已知可信真机 WqfIGg5r 同指纹) 为底, 只随机化"硬唯一标识"。
        /// </summary>
        public static DeviceProfile MinimalNewDevice()
        {
            var d = DeviceProfile.FromSample01();
            MinimalMock(d);
            return d;
        }

        /// <summary>
        /// 就地做<b>最小 mock</b>: <b>只随机化"硬唯一标识"(A 类) 及其强制派生字段</b>,
        /// 其余全部保持基线真机的自洽快照值 (机型指纹 + 环境/行为/时间戳/传感器/加密预算字段)。
        ///
        /// 目的: 以最小改动面让服务端把它当作"同机型的另一台真机"并下发新 pddid, 用于验证
        /// "设备过新无历史"是否为 render 硬风控(售罄)的根因 —— 若最小 mock 仍售罄, 则字段质量
        /// 已非变量, 结论收敛到设备信誉/养号 (而非注册指纹泄露 mock)。
        ///
        /// 与 <see cref="Randomize"/> 的区别: <b>不动</b> did_info 计数器 / battery / capacity /
        /// memory / boot_time / install_time / p90 / p7 / p2 / p30 / p49 / p125 / cpuFreq / volume /
        /// apk 安装段 / adb·dev 标志。这些保留基线真机值, 保证整机快照自洽。
        /// </summary>
        public static void MinimalMock(DeviceProfile d)
        {
            d.IsMock = true;

            // ===== 硬唯一标识 (不同物理设备必然不同; 服务端据此判为新设备/下发新 pddid) =====
            d.AndroidId = RandomHex(8);                 // 16 hex — 设备主标识
            d.Oaid = RandomHex(16);                     // 32 hex — 广告 ID
            d.SharedPreferenceId = RandomHex(16);       // 32 hex — 安装态标识 (MD5 长)
            d.Uuid = Guid.NewGuid().ToString();         // 标准 UUID
            d.P47 = P47Generator.New();                 // 会话标识 (x-p1 RC4 key 来源)
            d.InstallToken = Guid.NewGuid().ToString(); // per-install UUID
            d.MediaDrmWidevineId = RandomHex(32);       // Widevine deviceUniqueId (每台物理设备唯一)

            d.P125 = P125Codec.GenerateRandom();        // per-device 随机 UUID 加密 (保留会与基线设备碰撞)
            d.P2 = PddLib.Crypto.P2Codec.RandomizeUniqueValues(d.P2); // attestation verifiedBootKey/Hash 每台唯一
            // did_info: native 复合串, [3]=16hex(类硬件ID) / [8]=UUID 是设备唯一锚点 (01 报文 token105 含它,
            // 疑为服务端设备主键之一)。只随机化这两个身份段, 计数器[4..7]/时间段保留基线 (符合最小改动)。
            d.DidInfo = RandomizeDidInfo();

            byte[] macBytes = RandomMacBytes();
            d.P22Mac = MacToString(macBytes);

            // ===== 强制派生联动 (否则与新标识不自洽, 反而成破绽) =====
            d.IpList = BuildIpList(macBytes);           // wlan0/全局地址接口标识符 = 新 MAC 的 EUI-64
            long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            d.RecomputeUserEnv2(nowMs);                 // user_env2 内嵌 android_id → 必须重算
            // p10 = android_id, 由 Builder 内部自动取, 无需单独设

            // ===== 持久身份类 (heavy Randomize 改了这些才拿到新 pddid; 最小 mock 之前保留 → 被判旧设备) =====
            // 依据: "重度随机化能拿新 pddid, 最小 mock 返回旧 pddid" 的 delta 分析, 服务器设备锚点在此子集。
            // p49: 88 个系统文件 inode CSV, 每台/每次安装唯一且稳定 (经典持久指纹, 头号嫌疑)。
            d.P49 = P49Codec.RandomizeFromBaseline(d.P49);
            // p30: per-device 加密 blob (干净设备 = 空风险列表, 重新生成而非复用基线)。
            d.P30 = P30Codec.GenReportField("");
            // 安装/开机时间戳: 同一台"设备"的安装时间相同 → 换新的安装/开机时刻使其成为独立安装实例。
            long installMs = nowMs - RandomLong(7L * 86400_000, 180L * 86400_000);
            d.P46InstallTime = installMs;
            d.P90 = FormatPddTime(installMs);
            long nowSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            d.BootTime = nowSec - RandomLong(3600, 10L * 86400);
            // app 安装路径随机段 (Android10+ /data/app/~~seg1/pkg-seg2/): 每次安装唯一 (联动 type15.p75 / type16 maps)。
            d.ApkDirSeg1 = RandomInstallSeg();
            d.ApkDirSeg2 = RandomInstallSeg();
            // p7: "包名|base64token;" 的 token 疑为 per-install app 签名/标识 (delta 剩余嫌疑)。
            d.P7AbnormalApps = RandomizeP7(d.P7AbnormalApps);
            // 电池/容量: 半持久数值 (charge_counter/seq/cycle + 精确字节数), 真机间有差异。
            d.BatteryStatus = RandomizeBattery(d.BatteryStatus);
            d.TotalCapacity = PerturbSmall(d.TotalCapacity, 0.0005);
            d.TotalMemory = PerturbSmall(d.TotalMemory, 0.0003);
            d.AvailableCapacity = (long)(d.TotalCapacity * (0.25 + NextDouble() * 0.6));

            // ===== 新设备无历史会话 (清空上次 pddid 绑定的 cookie, 避免被链接回旧设备) =====
            d.BodyCookie = "";
            d.HeaderApiUid = "";

            // 仍保持基线不变: 机型指纹 (fingerprint/p4/model/soc/分辨率/传感器) +
            //   纯运行时行为量 (battery 电压温度电量/capacity/memory/cpuFreq/volume/did_info 计数器)。
            //   —— 这些真机每次读都变, 服务器无法用作设备主键, 保留可维持"老真机"自洽观感。
        }

        /// <summary>
        /// 就地随机化一个 DeviceProfile 的唯一性字段 (A/B/C 类), 保留 D 类机型指纹。
        /// </summary>
        public static void Randomize(DeviceProfile d)
        {
            d.IsMock = true;

            // ===== A. 硬唯一标识 =====
            d.AndroidId = RandomHex(8);                 // 16 hex
            d.Oaid = RandomHex(16);                     // 32 hex
            d.SharedPreferenceId = RandomHex(16);       // 32 hex (MD5 长)
            d.Uuid = Guid.NewGuid().ToString();         // 标准 UUID

            // p22 MAC: 先取字节 (供 ip_list EUI-64 联动), 再格式化
            byte[] macBytes = RandomMacBytes();
            d.P22Mac = MacToString(macBytes);
            d.P47 = P47Generator.New();                 // 会话随机标识 (x-p1 RC4 key 来源)
            d.InstallToken = Guid.NewGuid().ToString();  // 02 报文 per-install UUID
            // mediaDrm Widevine deviceUniqueId: 每台物理设备唯一 (32B) → 随机, 防判重复设备
            d.MediaDrmWidevineId = RandomHex(32);

            // ===== B. 关联派生 =====
            // install_time: 过去 7~180 天内的某时刻 (ms)
            long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long installMs = nowMs - RandomLong(7L * 86400_000, 180L * 86400_000);
            d.P46InstallTime = installMs;
            d.P90 = FormatPddTime(installMs);

            // boot_time: 过去 1 小时 ~ 10 天内开机 (秒)
            long nowSec = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            d.BootTime = nowSec - RandomLong(3600, 10L * 86400);

            // did_info: 随机化标识段 ([3]=16hex 类 android_id 变形, [8]=UUID), 保留格式
            d.DidInfo = RandomizeDidInfo();

            // ip_list: 随机化, 但 wlan0/全局地址的接口标识符 = p22 MAC 的 EUI-64 (与 MAC 自洽)
            d.IpList = BuildIpList(macBytes);

            // p7: 保留大型 app 包名, 随机化每个包名后的 base64 标识
            d.P7AbnormalApps = RandomizeP7(d.P7AbnormalApps);

            // battery_status: 随机化电压/温度/电量/循环次数等动态数值字段
            d.BatteryStatus = RandomizeBattery(d.BatteryStatus);

            // 容量/内存: 同型号设备出厂字节级波动 (total 小范围), available 大范围
            d.TotalCapacity = PerturbSmall(d.TotalCapacity, 0.0005);   // ±0.05%
            d.TotalMemory = PerturbSmall(d.TotalMemory, 0.0003);       // ±0.03%
            d.AvailableCapacity = (long)(d.TotalCapacity * (0.25 + NextDouble() * 0.6)); // 25%~85% 占用余量

            // 新设备无历史会话凭据
            d.BodyCookie = "";
            d.HeaderApiUid = "";

            // p2 attestation: 随机化 verifiedBootKey/verifiedBootHash (每台 root-of-trust 不同, 避免固定指纹)
            d.P2 = PddLib.Crypto.P2Codec.RandomizeUniqueValues(d.P2);

            // mock 干净设备建议关闭调试标志 (真机样本为 1)
            d.AdbEnabled = 0;
            d.DevelopmentEnabled = 0;

            // ===== C. 设备绑定加密 =====
            // p30: 干净设备 = 空风险列表加密 (不复刻样本的 hunter)
            d.P30 = P30Codec.GenReportField("");
            // user_env2: 用新 android_id + 当前时刻算基线 (发送时 RegisterClient 会按请求 ts 重算)
            d.RecomputeUserEnv2(nowMs);
            // p125: 每台设备独立随机 UUID 加密
            d.P125 = P125Codec.GenerateRandom();
            // p49: 基于样本基线 CSV, 只扰动"真实设备间会变化"的 inode (可写文件/sdcard/proc)
            d.P49 = P49Codec.RandomizeFromBaseline(d.P49);
            // app 安装路径随机段 (Android10+ /data/app/~~seg1/pkg-seg2/): 每台唯一。
            // ★ 同时喂 type15.p75 与 type16 maps 清单 (RegisterClient.Build07/Build16 联动), 保证一致。
            d.ApkDirSeg1 = RandomInstallSeg();
            d.ApkDirSeg2 = RandomInstallSeg();

            // ===== D 类里实际会动态变化的环境量 (机型不变, 但每次/每机取值不同) =====
            // cpuFrequency: 只随机 curFreq (实时频点), max/min (频率策略上下限) 保持不变
            d.CpuFrequencyJson = RandomizeCpuFreq(d.CpuFrequencyJson);
            // volume: 各音频流当前音量, 合理范围内随机
            d.VolumeJson = RandomizeVolume(d.VolumeJson);

            // ===== D. fingerprint / p4 / build_id / 机型 header 等保持不变 =====
        }

        // ==================== cpuFrequency / volume ====================

        /// <summary>
        /// 随机化 cpuFrequency 的 curFreq: 每核保留 maxFreq/minFreq, 在 [min,max] 内
        /// 取"频率步长 (gcd(min,max)) 的整数倍"作为 curFreq (近似合法 OPP 频点)。
        /// 输出紧凑 JSON, 键序/格式与样本一致, 供 Extra02Builder 原样嵌入。
        /// </summary>
        private static string RandomizeCpuFreq(string baselineJson)
        {
            using var doc = System.Text.Json.JsonDocument.Parse(baselineJson);
            var sb = new StringBuilder();
            sb.Append('[');
            bool first = true;
            foreach (var core in doc.RootElement.EnumerateArray())
            {
                if (!first) sb.Append(',');
                first = false;
                string max = core.GetProperty("maxFreq").GetString()!;
                string min = core.GetProperty("minFreq").GetString()!;
                long curHz = PickCurFreq(ParseHz(min), ParseHz(max));
                sb.Append("{\"maxFreq\":\"").Append(max)
                  .Append("\",\"minFreq\":\"").Append(min)
                  .Append("\",\"curFreq\":\"").Append(curHz).Append("Hz\"}");
            }
            sb.Append(']');
            return sb.ToString();
        }

        /// <summary>"3532800Hz" → 3532800</summary>
        private static long ParseHz(string s)
        {
            int i = s.IndexOf("Hz", StringComparison.Ordinal);
            string num = i >= 0 ? s[..i] : s;
            return long.TryParse(num, out long v) ? v : 0;
        }

        /// <summary>在 [min,max] 内取频率步长 (gcd) 的整数倍作为当前频点。</summary>
        private static long PickCurFreq(long min, long max)
        {
            if (max <= min) return min;
            long step = Gcd(min, max);
            if (step <= 0) step = max - min;
            long n = (max - min) / step;              // 可选步数
            long k = RandomNumberGenerator.GetInt32(0, (int)Math.Min(n, int.MaxValue) + 1);
            return min + step * k;
        }

        private static long Gcd(long a, long b)
        {
            while (b != 0) { (a, b) = (b, a % b); }
            return a < 0 ? -a : a;
        }

        /// <summary>
        /// 随机化 volume: 各音频流当前音量在合理范围内取值 (键序保持样本)。
        /// 范围依 Android 各 stream 常见上限设定, 避免超过设备可能的最大档位。
        /// </summary>
        private static string RandomizeVolume(string baselineJson)
        {
            using var doc = System.Text.Json.JsonDocument.Parse(baselineJson);
            var sb = new StringBuilder();
            sb.Append('{');
            bool first = true;
            foreach (var p in doc.RootElement.EnumerateObject())
            {
                if (!first) sb.Append(',');
                first = false;
                int v = p.Name switch
                {
                    "voiceCall" => RandomNumberGenerator.GetInt32(1, 8),   // 1~7
                    _ => RandomNumberGenerator.GetInt32(0, 16),            // 0~15
                };
                sb.Append('"').Append(p.Name).Append("\":").Append(v);
            }
            sb.Append('}');
            return sb.ToString();
        }

        // ==================== did_info ====================

        /// <summary>
        /// did_info 样本 10 段 (';' 分隔):
        ///   [0][1] 时间  [2] 0000000000000000  [3] 16hex(类android_id)  [4..7] 数字
        ///   [8] UUID  [9] 时间
        /// 随机化标识段 [3] 与 [8], 其余保留样本格式 (时间/数字与唯一性无强绑定)。
        /// </summary>
        private static string RandomizeDidInfo()
        {
            return
                "1970-01-08 07:39:40.359999986 +0800;" +
                "2025-07-31 19:43:46.371999992 +0800;" +
                "0000000000000000;" +
                RandomHex(8) + ";" +                    // [3] 16 hex
                "117898323;11880957;2025681;4960;" +
                Guid.NewGuid().ToString() + ";" +        // [8] UUID
                "1970-01-08 07:39:41.235999986 +0800;";
        }

        // ==================== 时间格式 ====================

        /// <summary>
        /// 复刻 p90 格式: "yyyy-MM-dd HH:mm:ss.fffffffff +0800" (东八区, 9 位纳秒)。
        /// 纳秒后 6 位用随机补足 (真机来自高精度时钟, 服务端不校验具体值)。
        /// </summary>
        private static string FormatPddTime(long unixMs)
        {
            var tz = TimeSpan.FromHours(8);
            var dto = DateTimeOffset.FromUnixTimeMilliseconds(unixMs).ToOffset(tz);
            int ms = dto.Millisecond;
            int nanoTail = RandomNumberGenerator.GetInt32(0, 1_000_000); // 后 6 位
            string nanos = (ms * 1_000_000 + nanoTail).ToString("D9", CultureInfo.InvariantCulture);
            return dto.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
                   + "." + nanos + " +0800";
        }

        // ==================== 随机原语 ====================

        /// <summary>n 字节随机 → 2n 位小写 hex。</summary>
        public static string RandomHex(int nBytes)
        {
            byte[] b = new byte[nBytes];
            RandomNumberGenerator.Fill(b);
            var sb = new StringBuilder(nBytes * 2);
            foreach (byte x in b) sb.Append(x.ToString("x2", CultureInfo.InvariantCulture));
            return sb.ToString();
        }

        /// <summary>
        /// Android 10+ 安装目录随机段: 16 字节随机 → base64url (含 "==" 填充, 22+2 字符),
        /// 与真机 /data/app/~~&lt;seg&gt; 命名一致 (Base64.URL_SAFE)。
        /// </summary>
        public static string RandomInstallSeg()
        {
            byte[] b = new byte[16];
            RandomNumberGenerator.Fill(b);
            return Convert.ToBase64String(b).Replace('+', '-').Replace('/', '_');
        }

        /// <summary>
        /// 随机 MAC 字节: 首字节设 locally-administered 位 (bit1=1)、清 multicast 位 (bit0=0)。
        /// </summary>
        public static byte[] RandomMacBytes()
        {
            byte[] b = new byte[6];
            RandomNumberGenerator.Fill(b);
            b[0] = (byte)((b[0] & 0xFC) | 0x02); // locally administered, unicast
            return b;
        }

        /// <summary>MAC 字节 → 大写 "XX:XX:XX:XX:XX:XX"。</summary>
        public static string MacToString(byte[] b)
            => string.Join(":", Array.ConvertAll(b, x => x.ToString("X2", CultureInfo.InvariantCulture)));

        /// <summary>随机 MAC (字节版 + 格式化的便捷封装)。</summary>
        public static string RandomMac() => MacToString(RandomMacBytes());

        // ==================== ip_list ====================

        /// <summary>
        /// 由 MAC 计算 EUI-64 接口标识符 (IPv6 后 64 位), 返回 4 段 "xxxx:xxxx:xxxx:xxxx"。
        /// 规则: 翻转 MAC 首字节 bit1, 中间插入 ff:fe。样本 26:9d:12:9b:ad:86 → 249d:12ff:fe9b:ad86。
        /// </summary>
        private static string Eui64Suffix(byte[] mac)
        {
            byte b0 = (byte)(mac[0] ^ 0x02);
            int[] words =
            {
                (b0 << 8) | mac[1],
                (mac[2] << 8) | 0xff,
                (0xfe << 8) | mac[3],
                (mac[4] << 8) | mac[5]
            };
            return string.Join(":", Array.ConvertAll(words, w => w.ToString("x4", CultureInfo.InvariantCulture)));
        }

        /// <summary>随机 4 段 IPv6 后缀 (临时地址/隐私扩展)。</summary>
        private static string RandomV6Suffix()
        {
            int[] w = new int[4];
            for (int i = 0; i < 4; i++) w[i] = RandomNumberGenerator.GetInt32(0, 0x10000);
            return string.Join(":", Array.ConvertAll(w, x => x.ToString("x4", CultureInfo.InvariantCulture)));
        }

        /// <summary>
        /// 构造 ip_list, 结构贴合样本: dummy0/wlan0 的 link-local、ULA 全局前缀 + EUI-64/临时地址、
        /// 内网 IPv4、tun0。wlan0 与全局地址的接口标识符联动 p22 MAC 的 EUI-64。
        /// </summary>
        private static string BuildIpList(byte[] mac)
        {
            string eui = Eui64Suffix(mac);
            // 随机 ULA 全局前缀 fdxx:xxxx:xxxx:xxxx
            int p1 = 0xfd00 | RandomNumberGenerator.GetInt32(0, 0x100);
            int p2 = RandomNumberGenerator.GetInt32(0, 0x10000);
            int p3 = RandomNumberGenerator.GetInt32(0, 0x10000);
            int p4 = RandomNumberGenerator.GetInt32(0, 0x10000);
            string prefix = $"{p1:x4}:{p2:x4}:{p3:x4}:{p4:x4}";

            int lan = RandomNumberGenerator.GetInt32(2, 254);
            int dummyTail = RandomNumberGenerator.GetInt32(0, 0x10000);

            var sb = new StringBuilder();
            sb.Append($"fe80::{RandomV6Suffix()}%dummy0;");
            sb.Append($"fe80::{eui}%wlan0;");
            sb.Append($"{prefix}:{eui};");
            sb.Append($"{prefix}:{RandomV6Suffix()};");
            sb.Append($"{prefix}:{RandomV6Suffix()};");
            sb.Append($"192.168.{RandomNumberGenerator.GetInt32(0, 256)}.{lan};");
            sb.Append($"fe80::{RandomV6Suffix()}%tun0;");
            sb.Append($"10.0.0.{RandomNumberGenerator.GetInt32(2, 254)};");
            return sb.ToString();
        }

        // ==================== p7 ====================

        /// <summary>
        /// p7 = "包名|base64标识;包名|base64标识;" (检测到的大型 app)。
        /// 保留包名结构, 随机化每个 '|' 后的 base64 值 (长度与原值一致)。
        /// </summary>
        private static string RandomizeP7(string p7)
        {
            if (string.IsNullOrEmpty(p7)) return p7;
            var sb = new StringBuilder();
            foreach (string entry in p7.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                int bar = entry.IndexOf('|');
                if (bar < 0) { sb.Append(entry).Append(';'); continue; }
                string pkg = entry[..bar];
                string b64 = entry[(bar + 1)..];
                // 原 base64 解出字节数, 用等长随机字节重新 base64
                int nBytes = Math.Max(1, b64.TrimEnd('=').Length * 3 / 4);
                byte[] rnd = new byte[nBytes];
                RandomNumberGenerator.Fill(rnd);
                sb.Append(pkg).Append('|').Append(Convert.ToBase64String(rnd)).Append(';');
            }
            return sb.ToString();
        }

        // ==================== battery_status ====================

        /// <summary>battery_status = "k,v,k,v,..." 逗号交替。随机化部分动态数值字段。</summary>
        private static string RandomizeBattery(string battery)
        {
            if (string.IsNullOrEmpty(battery)) return battery;
            // 末尾常有空段, Split 后照样重组 (保留结构)
            string[] t = battery.Split(',');
            for (int i = 0; i + 1 < t.Length; i += 2)
            {
                string key = t[i];
                string val = t[i + 1];
                t[i + 1] = key switch
                {
                    "level" => RandIntStr(20, 100),                 // 电量 %
                    "temperature" => RandIntStr(230, 410),          // 温度 (0.1°C, 23~41°C)
                    "voltage" => RandIntStr(3700, 4400),            // mV
                    "voltage_now" => string.IsNullOrEmpty(val) ? val : RandIntStr(3700000, 4400000), // µV
                    "seq" => RandIntStr(1000, 20000),
                    "charge_counter" => RandIntStr(3000000, 7000000),
                    "android.os.extra.CYCLE_COUNT" => RandIntStr(1, 400),
                    "icon-small" => RandIntStr(17000000, 17999999),
                    _ => val
                };
            }
            return string.Join(",", t);
        }

        private static string RandIntStr(int minIncl, int maxIncl)
            => RandomNumberGenerator.GetInt32(minIncl, maxIncl + 1).ToString(CultureInfo.InvariantCulture);

        /// <summary>[minInclusive, maxInclusive] 范围内的随机 long。</summary>
        private static long RandomLong(long minInclusive, long maxInclusive)
        {
            if (maxInclusive <= minInclusive) return minInclusive;
            ulong range = (ulong)(maxInclusive - minInclusive);
            Span<byte> buf = stackalloc byte[8];
            RandomNumberGenerator.Fill(buf);
            ulong v = BitConverter.ToUInt64(buf) % (range + 1);
            return minInclusive + (long)v;
        }

        /// <summary>[0,1) 的随机 double (加密级)。</summary>
        private static double NextDouble()
            => RandomNumberGenerator.GetInt32(0, 1_000_000) / 1_000_000.0;

        /// <summary>对一个量做 ±fraction 比例的小范围扰动 (同型号设备字节级差异)。</summary>
        private static long PerturbSmall(long v, double fraction)
        {
            double f = 1.0 + (NextDouble() * 2 - 1) * fraction; // 1±fraction
            long nv = (long)(v * f);
            return nv < 1 ? v : nv;
        }
    }
}
