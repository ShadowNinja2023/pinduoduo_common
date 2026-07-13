using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Json;

namespace PddLib.Register
{
    /// <summary>
    /// 转换报告: 记录每个 PDD 字段的来源与状态。
    ///   Mapped   = 从淘宝检测项成功映射
    ///   Defaulted= 无直接来源, 保留 PDD 基线值 (可用但非本机真实)
    ///   Missing  = 无法从淘宝数据构造, 需另想办法 (标注原因)
    /// </summary>
    public class ConversionReport
    {
        public List<(string Field, string Source, string Value)> Mapped { get; } = new();
        public List<(string Field, string Reason)> Defaulted { get; } = new();
        public List<(string Field, string Reason)> Missing { get; } = new();

        public void Map(string field, string source, string value) => Mapped.Add((field, source, Trunc(value)));
        public void Default(string field, string reason) => Defaulted.Add((field, reason));
        public void Miss(string field, string reason) => Missing.Add((field, reason));

        private static string Trunc(string s) => s.Length > 80 ? s[..80] + "…" : s;

        public string Summary()
            => $"映射成功 {Mapped.Count} | 保留基线 {Defaulted.Count} | 缺失待办 {Missing.Count}";
    }

    /// <summary>
    /// 淘宝(SGMain)设备检测项 → 拼多多 <see cref="DeviceProfile"/> 基准转换器。
    ///
    /// 职责: 把一台真实淘宝设备的硬件/系统指纹, 转换成同机型的 PDD DeviceProfile "基准"。
    /// 之后由 <see cref="DeviceMocker"/> 在此基准上随机化唯一值 → 同品牌机型的全新 mock 设备。
    ///
    /// 映射依据: DETECT_ITEMS_CATALOG.md。仅映射可靠可得的硬件/系统字段;
    /// PDD 私有加密字段 (p49/p30/p125/user_env2/p50/p65/p85/p2/fk_data 等) 淘宝侧无对应,
    /// 记入 Missing (由 PDD 自身 codec 生成或需另解决)。
    /// </summary>
    public static class TaobaoToPddConverter
    {
        public static (DeviceProfile device, ConversionReport report) Convert(TaobaoDeviceRecord r)
        {
            var d = new DeviceProfile { IsMock = true };
            var rep = new ConversionReport();

            // ===== 硬件/系统指纹 (D 类, 可靠映射) =====

            // android_id ← 0174:cecf getAndroidId
            MapStr(r.Get("0174", "cecf"), v => d.AndroidId = v, "AndroidId", "0174:cecf", rep);

            // fingerprint ← fd52:5e07 ro.build.fingerprint
            string? fp = r.Get("fd52", "5e07");
            if (!string.IsNullOrEmpty(fp))
            {
                d.Fingerprint = fp;
                rep.Map("Fingerprint", "fd52:5e07", fp);
                // build_id = fingerprint 第4段 (AOSP 风格 Build.ID)
                var parts = fp.Split('/');
                if (parts.Length >= 4) { d.BuildId = parts[3]; rep.Map("BuildId", "fd52:5e07[3]", parts[3]); }
            }
            else rep.Miss("Fingerprint", "无 fd52:5e07");

            MapStr(r.Get("2b23", "5e07"), v => d.Brand = v, "Brand", "2b23:5e07", rep);
            MapStr(r.Get("aaca", "5e07"), v => d.Model = v, "Model", "aaca:5e07", rep);
            MapStr(r.Get("f471", "5e07"), v => d.Osv = v, "Osv", "f471:5e07", rep);

            // 02/扩展机型字段
            MapStr(r.Get("1463", "5e07"), v => d.Manufacturer = v, "Manufacturer", "1463:5e07", rep);
            MapStr(r.Get("b07c", "5e07"), v => d.Board = v, "Board", "b07c:5e07", rep);
            MapStr(r.Get("389e", "5e07"), v => d.Device = v, "Device", "389e:5e07", rep);
            // ro.build.product 常 = model
            MapStr(r.Get("aaca", "5e07"), v => d.Product = v, "Product", "aaca:5e07(=model)", rep);
            // board.platform: 48b2 常缺, 用 SoC 派生
            string? soc = TryJsonStr(r.Get("e654", "9ed0"), "soc");
            if (!string.IsNullOrEmpty(soc)) { d.BoardPlatform = soc!.ToLowerInvariant(); rep.Map("BoardPlatform", "e654:9ed0.soc", d.BoardPlatform); }
            else rep.Default("BoardPlatform", "无 48b2/e654, 保留基线");

            // ===== 存储/内存 =====
            MapLong(r.Get("b7ab", "cecf"), v => d.TotalCapacity = v, "TotalCapacity", "b7ab:cecf(sdcard bytes)", rep);
            // totalmem: d38e = /proc/meminfo MemTotal (KB) → bytes
            if (long.TryParse(r.Get("d38e", "cecf"), out long memKb) && memKb > 0)
            {
                d.TotalMemory = memKb * 1024L;
                rep.Map("TotalMemory", "d38e:cecf(KB*1024)", d.TotalMemory.ToString());
            }
            else rep.Default("TotalMemory", "无 d38e:cecf, 保留基线");

            // ===== 启动时间 (ms→s) =====
            if (long.TryParse(r.Get("a506", "cecf"), out long bootMs) && bootMs > 0)
            {
                d.BootTime = bootMs / 1000L;
                rep.Map("BootTime", "a506:cecf(ms/1000)", d.BootTime.ToString());
            }
            else rep.Default("BootTime", "无 a506:cecf, 保留基线");

            // ===== 屏幕 =====
            // 真实分辨率 a2c2 "W*H"; 可用区 aaa0; dpi 从 b7db:b151
            string? realRes = r.Get("a2c2", "cecf");   // 用于 04 resolution (下游 baseline, 暂记 report)
            string? usableRes = r.Get("aaa0", "cecf");
            var (uw, uh) = ParseWxH(usableRes ?? realRes);
            if (uw > 0) { d.ScreenWidth = uw; d.ScreenHeight = uh; rep.Map("Screen", "aaa0/a2c2:cecf", $"{uw}x{uh}"); }
            else rep.Default("Screen", "无 a2c2/aaa0, 保留基线");
            // 04 分辨率字段: resolution=真实(a2c2, 'x' 分隔), p57=可用区(aaa0, '*' 分隔)
            if (!string.IsNullOrEmpty(realRes)) { d.ResolutionReal = realRes!.Replace('*', 'x'); rep.Map("ResolutionReal(04)", "a2c2:cecf", d.ResolutionReal); }
            if (!string.IsNullOrEmpty(usableRes)) { d.ResolutionUsable = usableRes!.Replace('x', '*'); rep.Map("ResolutionUsable(p57)", "aaa0:cecf", d.ResolutionUsable); }
            int dpi = ParseLeadingInt(TryJsonRawDpi(r.Get("b7db", "b151")));
            if (dpi > 0) { d.Dpi = dpi; d.Dpr = Math.Round(dpi / 160.0, 2); rep.Map("Dpi/Dpr", "b7db:b151.dpi", $"{dpi}/{d.Dpr.ToString(CultureInfo.InvariantCulture)}"); }
            else rep.Default("Dpi/Dpr", "无 b7db dpi, 保留基线");

            // characteristics ← d32c:cecf (Tablet→tablet, 其他→空)
            string? devType = r.Get("d32c", "cecf");
            if (!string.IsNullOrEmpty(devType)) { d.Characteristics = devType!.Equals("Tablet", StringComparison.OrdinalIgnoreCase) ? "tablet" : ""; rep.Map("Characteristics", "d32c:cecf", d.Characteristics); }
            else rep.Default("Characteristics", "无 d32c:cecf, 保留基线");

            // p18 时区 ← f62f:cecf
            MapStr(r.Get("f62f", "cecf"), v => d.TimeZone = v, "TimeZone(p18)", "f62f:cecf", rep);
            // p20 SoC ← e654:9ed0.soc
            if (!string.IsNullOrEmpty(soc)) { d.Soc = soc!; rep.Map("Soc(p20)", "e654:9ed0.soc", soc!); }
            else rep.Default("Soc(p20)", "无 e654.soc, 保留基线");

            // opertor_info (02) ← caba:7326 (多卡取第一张 LOADED); 格式 SPN:numeric:网络名:phoneType:iso
            //   字段0(SPN)/字段2(网络名) 都用 caba.alpha (缺 gsm.sim.operator.alpha, 按读出值填, 不管短码)
            string? oper = BuildOpertorInfo(r.Get("caba", "7326"));
            if (oper != null) { d.OpertorInfo = MetaInfoSubBuilder.JavaUrlEncode(oper); rep.Map("OpertorInfo(02)", "caba:7326", oper); }
            else rep.Default("OpertorInfo(02)", "无 SIM(state≠LOADED)或无 caba, 保留基线 :::0:");

            // p8 系统启动次数 ← ef95:e78e (boot_count)
            if (int.TryParse(r.Get("ef95", "e78e"), out int bootCnt) && bootCnt > 0)
            { d.BootCount = bootCnt; rep.Map("BootCount(p8)", "ef95:e78e", bootCnt.ToString()); }
            else rep.Default("BootCount(p8)", "无 ef95:e78e, 保留基线");

            // p19 电池容量 mAh ← 9a2f:a78f
            if (int.TryParse(r.Get("9a2f", "a78f"), out int cap) && cap > 0)
            { d.BatteryCapacityMah = cap; rep.Map("BatteryCapacity(p19)", "9a2f:a78f", cap.ToString()); }
            else rep.Default("BatteryCapacity(p19)", "无 9a2f:a78f, 保留基线");

            // p51/p52 铃声/通知音 URI ← f17a:e78e (ringtone / alarm_alert)
            string? f17a = r.Get("f17a", "e78e");
            string? ring = TryJsonStr(f17a, "ringtone");
            string? alarm = TryJsonStr(f17a, "alarm_alert");
            if (!string.IsNullOrEmpty(ring)) { d.RingtoneUri = ring!; rep.Map("RingtoneUri(p51)", "f17a:e78e.ringtone", ring!); }
            else rep.Default("RingtoneUri(p51)", "无 f17a.ringtone, 保留基线");
            if (!string.IsNullOrEmpty(alarm)) { d.NotificationUri = alarm!; rep.Map("NotificationUri(p52)", "f17a:e78e.alarm_alert", alarm!); }
            else rep.Default("NotificationUri(p52)", "无 f17a.alarm_alert, 保留基线");

            // ===== 输入法 (146f TEA 已解) =====
            string? im = TryJsonStr(r.Get("146f", "e78e"), "default") ?? TryJsonStr(r.Get("146f", "b151"), "e_0");
            MapStr(im, v => d.InputMethod = v, "InputMethod", "146f:e78e.default", rep);

            // ===== p4 uname ← c478:6c6d =====
            string? uname = r.Get("c478", "6c6d");
            if (!string.IsNullOrEmpty(uname))
            {
                // p4 是 {"2": uname} 且做 JavaUrlEncode 前的原文 (空格→+ 由 Builder 处理? p4 是原样字段)
                d.P4 = "{\"2\":\"" + uname!.Replace(" ", "+").Replace(":", "%3A").Replace("#", "%23") + "\"}";
                rep.Map("P4(uname)", "c478:6c6d", uname!);
            }
            else rep.Default("P4(uname)", "无 c478:6c6d, 保留基线");

            // ===== 电池 (91d5 JSON → 覆盖基线 kv 的 level/temperature/voltage) =====
            TryFillBattery(d, r.Get("91d5", "cecf"), rep);

            // ===== MAC (真实 wlan0 Android11+ 拿不到; 用 SDK 持久 0864:e097) =====
            string? mac = r.Get("0864", "e097");
            if (!string.IsNullOrEmpty(mac)) { d.P22Mac = mac!.ToUpperInvariant(); rep.Map("P22Mac", "0864:e097(SDK持久)", d.P22Mac); }
            else rep.Default("P22Mac", "无真实/持久 MAC, 保留基线(mocker 随机)");

            // ===== 安装时间 f75f:cecf "yyyy-MM-dd HH:mm:ss.fff" → ms =====
            if (TryParsePddTime(r.Get("f75f", "cecf"), out long installMs))
            {
                d.P46InstallTime = installMs;
                d.P90 = r.Get("f75f", "cecf")!.Trim() + " +0800";
                rep.Map("InstallTime/P90", "f75f:cecf", installMs.ToString());
            }
            else rep.Default("InstallTime/P90", "无 f75f:cecf, 保留基线");

            // ===== 清洁化检测标志 =====
            d.Root = 0; d.RomStatus = 0; d.AdbEnabled = 0; d.DevelopmentEnabled = 0;
            d.Sno = "unknown";
            rep.Map("Root/RomStatus/Adb...", "常量(清洁)", "0");

            // ===== 缺失: PDD 私有加密/私有字段 (淘宝侧无对应) =====
            rep.Miss("Oaid", "淘宝仅 GAID(c07a), 无 OAID → mocker 随机 (PDD OAID)");
            rep.Miss("SharedPreferenceId", "PDD 私有随机 → mocker 随机");
            rep.Miss("Uuid", "PDD 私有 → 可用 0141:bbe0 或 mocker 随机");
            rep.Miss("MediaDrmWidevineId", "淘宝不采集 Widevine → mocker 随机");
            rep.Miss("P49/P30/P125/UserEnv2", "PDD libpdd_secure/libdyncommon 输出, 淘宝无对应 → PDD codec 生成");
            rep.Miss("P50/P65/P85/P53/P68", "PDD RC4 私有字段 (含应用版本/输入法清单等), 淘宝无对应 → PDD baseline/codec");
            rep.Miss("P2(KeyStore attest)", "PDD 采 attestation, 淘宝 c662 结构不同 → PDD baseline 或另采");
            rep.Miss("fk_data/P7", "PDD 私有格式, 淘宝无直接对应 → baseline/codec");
            rep.Default("P2(attestation)", "证书链 Lenovo 基线; mocker 随机化 verifiedBootKey/Hash (P2Codec)");
            rep.Miss("InputDevice", "触屏/触控笔描述符, 淘宝仅有传感器(6980/aad5), 无触屏 → baseline");
            rep.Miss("CpuFrequency", "淘宝仅 cpu0 max(a5a4)+核数(c342), 缺 per-core min/cur → baseline(核数可校正)");
            rep.Miss("DidInfo", "PDD 内部复合串, mocker 随机化 [3]hex/[8]uuid, 无需淘宝来源");

            // uuid: 若有 0141 用之作基准 (mocker 仍会随机)
            MapStr(r.Get("0141", "bbe0"), v => d.Uuid = v, "Uuid(基准)", "0141:bbe0", rep);

            // CPU 核数 ← c342:cecf getCpuNum
            if (int.TryParse(r.Get("c342", "cecf"), out int cores) && cores > 0)
            { d.CpuCore = cores; rep.Map("CpuCore", "c342:cecf", cores.ToString()); }
            else rep.Default("CpuCore", "无 c342:cecf, 保留基线");

            // ===== 二次派生: ip_list ← 5de9:2109 (iface→IP 映射 → PDD 分号串) =====
            string? ipList = BuildPddIpList(r.Get("5de9", "2109"));
            if (!string.IsNullOrEmpty(ipList)) { d.IpList = ipList!; rep.Map("IpList", "5de9:2109(派生)", ipList!); }
            else rep.Default("IpList", "无 5de9:2109, 保留基线(mocker 随机)");

            return (d, rep);
        }

        // ---------------- helpers ----------------

        private static void MapStr(string? val, Action<string> set, string field, string src, ConversionReport rep)
        {
            if (!string.IsNullOrEmpty(val)) { set(val!); rep.Map(field, src, val!); }
            else rep.Default(field, $"无 {src}, 保留基线");
        }

        private static void MapLong(string? val, Action<long> set, string field, string src, ConversionReport rep)
        {
            if (long.TryParse(val, out long v) && v > 0) { set(v); rep.Map(field, src, v.ToString()); }
            else rep.Default(field, $"无 {src}, 保留基线");
        }

        private static (int w, int h) ParseWxH(string? s)
        {
            if (string.IsNullOrEmpty(s)) return (0, 0);
            var parts = s.Replace('x', '*').Split('*');
            if (parts.Length == 2 && int.TryParse(parts[0], out int w) && int.TryParse(parts[1], out int h))
                return (w, h);
            return (0, 0);
        }

        private static int ParseLeadingInt(string? s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            int i = 0; while (i < s.Length && char.IsDigit(s[i])) i++;
            return i > 0 && int.TryParse(s[..i], out int v) ? v : 0;
        }

        private static string? TryJsonStr(string? json, string key)
        {
            if (string.IsNullOrEmpty(json)) return null;
            try { using var doc = JsonDocument.Parse(json); return doc.RootElement.TryGetProperty(key, out var e) ? e.GetString() : null; }
            catch { return null; }
        }

        /// <summary>b7db:b151 里 dpi 值形如 "560(450...)"; 取其字符串。</summary>
        private static string? TryJsonRawDpi(string? json)
        {
            if (string.IsNullOrEmpty(json)) return null;
            try { using var doc = JsonDocument.Parse(json); return doc.RootElement.TryGetProperty("dpi", out var e) ? e.GetString() : null; }
            catch { return null; }
        }

        private static void TryFillBattery(DeviceProfile d, string? json, ConversionReport rep)
        {
            if (string.IsNullOrEmpty(json)) { rep.Default("BatteryStatus", "无 91d5:cecf, 保留基线"); return; }
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                string Get(string k) => root.TryGetProperty(k, out var e)
                    ? (e.ValueKind == JsonValueKind.Number ? e.GetRawText() : e.GetString() ?? "") : "";
                string level = Get("level"), temp = Get("temperature"), volt = Get("voltage"), status = Get("status");
                string b = d.BatteryStatus;
                b = ReplaceKv(b, "level", level);
                b = ReplaceKv(b, "temperature", temp);
                b = ReplaceKv(b, "voltage", volt);
                b = ReplaceKv(b, "status", status);
                d.BatteryStatus = b;
                rep.Map("BatteryStatus", "91d5:cecf(level/temp/volt/status)", $"level={level} temp={temp}");
            }
            catch { rep.Default("BatteryStatus", "91d5 解析失败, 保留基线"); }
        }

        /// <summary>替换 "k,v," 逗号 kv 串里某 key 的值 (PDD battery_status 格式)。</summary>
        private static string ReplaceKv(string csv, string key, string newVal)
        {
            if (string.IsNullOrEmpty(newVal)) return csv;
            var t = csv.Split(',');
            for (int i = 0; i + 1 < t.Length; i += 2)
                if (t[i] == key) { t[i + 1] = newVal; break; }
            return string.Join(",", t);
        }

        /// <summary>
        /// 5de9:2109 (iface→IP 的 JSON, 含重复键) → PDD ip_list 分号串。
        /// link-local (fe80::) 加 %iface 后缀; 全局 IPv6/IPv4 裸地址; 跳过 lo/::1/127.0.0.1。
        /// 保留原始顺序与重复 (用正则抽取, 不走 JsonDocument, 因有重复键)。
        /// </summary>
        public static string? BuildPddIpList(string? json)
        {
            if (string.IsNullOrEmpty(json)) return null;
            var matches = System.Text.RegularExpressions.Regex.Matches(
                json!, "\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");
            var sb = new System.Text.StringBuilder();
            int n = 0;
            foreach (System.Text.RegularExpressions.Match m in matches)
            {
                string iface = m.Groups[1].Value.Trim();
                string ip = m.Groups[2].Value.Trim();
                if (iface == "lo" || ip == "::1" || ip == "127.0.0.1" || ip.Length == 0) continue;
                string entry = ip.StartsWith("fe80", StringComparison.OrdinalIgnoreCase)
                    ? $"{ip}%{iface}"   // link-local 需带接口名
                    : ip;               // 全局 IPv6 / IPv4 裸地址
                sb.Append(entry).Append(';');
                n++;
            }
            return n > 0 ? sb.ToString() : null;
        }

        /// <summary>
        /// caba:7326 (运营商 JSON, 字段多卡逗号分隔) → PDD opertor_info 原文
        ///   = "SPN:networkNumeric:networkName:phoneType:simIso" (SPN/网络名都用 alpha)。
        /// 首张卡 state≠LOADED (无 SIM) 返回 null → 调用方回落基线 ":::0:"。
        /// </summary>
        private static string? BuildOpertorInfo(string? cabaJson)
        {
            if (string.IsNullOrEmpty(cabaJson)) return null;
            try
            {
                using var doc = JsonDocument.Parse(cabaJson);
                var root = doc.RootElement;
                string F(string k) => root.TryGetProperty(k, out var e) ? (e.GetString() ?? "") : "";
                string state = First(F("state"));
                if (!state.Equals("LOADED", StringComparison.OrdinalIgnoreCase)) return null;  // 无 SIM
                string alpha = First(F("alpha"));
                string numeric = First(F("numeric"));
                string iso = First(F("iso"));
                string ptype = First(F("phone_type"));
                return $"{alpha}:{numeric}:{alpha}:{ptype}:{iso}";
            }
            catch { return null; }
        }

        /// <summary>逗号分隔多卡值取第一张。</summary>
        private static string First(string csv)
            => string.IsNullOrEmpty(csv) ? "" : csv.Split(',')[0];

        private static bool TryParsePddTime(string? s, out long ms)
        {
            ms = 0;
            if (string.IsNullOrEmpty(s)) return false;
            if (DateTime.TryParse(s.Trim(), CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal, out var dt))
            {
                ms = new DateTimeOffset(dt, TimeSpan.FromHours(8)).ToUnixTimeMilliseconds();
                return true;
            }
            return false;
        }
    }
}
