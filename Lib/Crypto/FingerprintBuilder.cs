using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Encodings.Web;
using PddLib.Register;

namespace PddLib.Crypto
{
    /// <summary>
    /// 从 DeviceProfile 构造登录 fingerprint / touchevent 明文 JSON 及加密字段值。
    ///
    /// - 身份/机型/硬件字段取自 DeviceProfile;
    /// - 运行时/传感器类字段 (cpuUsage/frequency/gyroscopeSensor/volume/...) 取机型基线 (FingerprintBaseline);
    /// - 时间字段 (currentTime) 用本次请求 ts, 与 info2/meta 自洽。
    /// 字段名逐字复刻样本 (含 PDD 拼写错误 "simOperatroName")。
    /// 详见 docs/04_device_register/15_fingerprint_touchevent_analysis.md。
    /// </summary>
    public static class FingerprintBuilder
    {
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping   // 不转义 "/" 等
        };

        // ==================== fingerprint ====================

        /// <summary>构造 fingerprint 明文 JSON (约 55 字段, 保持样本字段顺序)。</summary>
        public static string BuildJson(DeviceProfile d, long? currentTimeMs = null)
        {
            long nowMs = currentTimeMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var b = FingerprintBaseline;

            // 保持样本字段顺序; Dictionary 按插入顺序序列化
            var m = new Dictionary<string, object?>
            {
                ["cpuUsage"] = b.CpuUsage,
                ["availableCapacity"] = d.AvailableCapacity,
                ["appVersion"] = d.AppVersion,
                ["simCountryIso"] = d.SimCountryIso,
                ["systemAppName"] = Array.Empty<string>(),
                ["connectType"] = b.ConnectType,
                ["operateTime"] = b.OperateTime,
                ["mcc"] = d.NetworkMcc,
                ["basebandversion2"] = b.Basebandversion2,
                ["frequency"] = b.Frequency,
                ["gyroscopeSensor"] = b.GyroscopeSensor,
                ["totalCapacity"] = d.TotalCapacity,
                ["model"] = d.Model,
                ["id"] = d.AndroidId,
                ["brand"] = d.Brand,
                ["networkOperatorName"] = d.NetworkOperatorName,
                ["perCpuUsage"] = b.PerCpuUsage,
                ["bootTime"] = d.BootTime * 1000L,
                ["buildTime"] = d.BuildDateUtc * 1000L,
                ["lightSensor"] = b.LightSensor,
                ["simState"] = d.SimState,
                ["dataState"] = d.DataState,
                ["currentTime"] = nowMs,
                ["volume"] = b.Volume,
                ["basebandversion1"] = b.Basebandversion1,
                ["simOperatroName"] = d.SimOperatorName,   // ← PDD 原字段名拼写错误, 原样保留
                ["standbyTime"] = b.StandbyTime,
                ["kernelVersion"] = b.KernelVersion,
                ["sdkVersion"] = d.SdkInt,
                ["device"] = d.Device,
                ["buildFingerprint"] = d.Fingerprint,
                ["dataActivity"] = d.DataActivity,
                ["cpuType"] = b.CpuType,
                ["installTime"] = d.P46InstallTime,
                ["mac"] = "",                              // 高版本取不到 → 空
                ["manufacturer"] = d.Manufacturer,
                ["sc"] = d.ResolutionReal.Replace("x", ","),  // "1520x1904" → "1520,1904"
                ["osVersion"] = d.Osv,
                ["prop"] = d.BuildPropTimeUtc * 1000L,
                ["root"] = d.Root != 0,
                ["sn"] = d.Sno,
                ["appDetect"] = Array.Empty<string>(),
                ["cpuCore"] = d.CpuCore,
                ["batteryLevel"] = b.BatteryLevel,
                ["networkCountryIso"] = d.NetworkCountryIso,
                ["mnc"] = d.NetworkMnc,
                ["os"] = "Android",
                ["appName"] = Array.Empty<string>(),
                ["display"] = d.Display,
                ["appCnt"] = 0,
                ["densityDpi"] = d.Dpi,
                ["totalMemory"] = d.TotalMemory,
                ["availableMemory"] = b.AvailableMemory,
                ["batteryStatus"] = b.BatteryStatus,
                ["screenBrightness"] = b.ScreenBrightness,
                ["board"] = d.Board,
            };
            return JsonSerializer.Serialize(m, JsonOpts);
        }

        /// <summary>构造 fingerprint 字段值 {"key","data"} (GZIP+AES+RSA)。</summary>
        public static string BuildField(DeviceProfile d, long? currentTimeMs = null, byte[]? random32 = null)
            => FingerprintCodec.Encrypt(BuildJson(d, currentTimeMs), random32);

        // ==================== touchevent ====================

        /// <summary>构造 touchevent 明文 JSON。默认未交互态 (send_code 场景)。</summary>
        public static string BuildTouchEventJson()
        {
            var m = new Dictionary<string, object?>
            {
                ["mobileInputEditStartTime"] = -1,
                ["mobileInputEditFinishTime"] = -1,
                ["mobileInputKeyboardEvent"] = "0|0|0|",
                ["sendSmsButtonTouchPoint"] = "",
                ["sendSmsButtonClickTime"] = -1,
                ["smsInputEditStartTime"] = -1,
                ["smsInputEditFinishTime"] = -1,
                ["smsInputKeyboardEvent"] = "0|0|0|",
                ["loginButtonTouchPoint"] = "",
                ["loginButtonClickTime"] = -1,
            };
            return JsonSerializer.Serialize(m, JsonOpts);
        }

        /// <summary>构造 touchevent 字段值 {"key","data"}。random32 传 fingerprint 同一把可复刻同请求共用 key。</summary>
        public static string BuildTouchEventField(byte[]? random32 = null)
            => FingerprintCodec.Encrypt(BuildTouchEventJson(), random32);

        // ==================== 机型/运行时基线 ====================

        /// <summary>fingerprint 里运行时/传感器类字段的机型基线 (取自 Lenovo TB322FC 样本)。</summary>
        public class FpBaseline
        {
            public string CpuUsage = "5.27%";
            public string ConnectType = "WIFI";
            public long OperateTime = 1128117970;
            public string Basebandversion1 = "";
            public string Basebandversion2 = "";
            public string CpuType = "";
            public long StandbyTime = 0;
            public string BatteryLevel = "89.00%";
            public long AvailableMemory = 6744539136;
            public int BatteryStatus = 2;
            public int ScreenBrightness = 40;
            public string KernelVersion =
                "Linux version 6.6.89-android15-8-g14220ae4ce65-ab13680582-4k (runner@runnervmg1sw1) " +
                "(Android (11368308, +pgo, +bolt, +lto, +mlgo, based on r510928) clang version 18.0.0 " +
                "(https://android.googlesource.com/toolchain/llvm-project 477610d4d0d988e69dbc3fae4fe86bff3f07f2b5), " +
                "LLD 18.0.0) #1 SMP PREEMPT Mon Jun 23 07:30:57 UTC 2025";
            public string[] PerCpuUsage = { "3.33%", "1.96%", "0.57%", "0.6%", "0.74%", "0.81%", "19.57%", "14.94%" };
            public object GyroscopeSensor = new Dictionary<string, object?>
            {
                ["name"] = "icm4x6xa Gyroscope Non-wakeup", ["vendor"] = "TDK-Invensense"
            };
            public object LightSensor = new Dictionary<string, object?>
            {
                ["name"] = "mn Ambient Light Sensor Non-wakeup", ["vendor"] = "eminent", ["data"] = Array.Empty<object>()
            };
            public object Volume = new Dictionary<string, object?>
            {
                ["system"] = 8, ["voiceCall"] = 5, ["ring"] = 8, ["alarm"] = 8, ["music"] = 11, ["notification"] = 8
            };
            public object[] Frequency = BuildFreq();

            private static object[] BuildFreq()
            {
                object Core(string mx, string mn, string cur) => new Dictionary<string, object?>
                { ["maxFreq"] = mx, ["minFreq"] = mn, ["curFreq"] = cur };
                var big = Core("4320000Hz", "1017600Hz", "4320000Hz");
                var little = Core("3532800Hz", "384000Hz", "1996800Hz");
                return new[] { little, little, little, little, little, little, big, big };
            }
        }

        private static readonly FpBaseline FingerprintBaseline = new();
    }
}
