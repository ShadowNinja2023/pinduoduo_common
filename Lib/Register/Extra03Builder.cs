using System;
using System.Security.Cryptography;
using System.Text;

namespace PddLib.Register
{
    /// <summary>
    /// 组装 03 报文 (POST /api/phantom/gbdbpdv/extra, data_type=20, SE.us 安全检测) 的明文。
    ///
    /// ★ 双层结构 (见 docs/04_device_register/10_request03_extra_analysis.md):
    ///   外层明文 (6 字段, libpdd_secure ng):
    ///     {"version":1,"uid":"","app_name":"pdd","pddid":"...","data_type":20,
    ///      "platform":"android","s_f_d":"&lt;内层{key,data}字符串&gt;"}
    ///   内层明文 (24 字段干净检测结果, libdyncommon us):
    ///     {"dynver":...,"rootInfo":...,"rand":...,"frida_detect":"{}",...}
    ///
    /// 转义差异 (实测):
    ///   - 内层 JSON: 标准 JSON, 转义 '"' '\' 但 **不转义 '/'**; 所有字段值都是字符串。
    ///   - 外层 JSON + encryptInfo: org.json 风格, 转义 '/' → '\/' (复用 Extra02Builder.JsonStr/WrapBody)。
    ///
    /// mock 策略: 不含 8f70d/5b766/y5dx/zt12t/zddgq (服务端 AB 门控组, 真机当前也不发);
    ///   rand 每次随机; adb_* 联动 device.AdbEnabled; 其余 clean 基线。
    /// </summary>
    public static class Extra03Builder
    {
        // ==================== 内层 (s_f_d) ====================

        /// <summary>
        /// 构造内层检测明文 JSON (24 字段, UTF-8)。
        /// </summary>
        /// <param name="d">设备指纹 (model_sys_fingerprint = d.Fingerprint; adb_* 联动 d.AdbEnabled)</param>
        /// <param name="randB64">rand 字段值; null 则随机生成 (容器头 + arc4random 等价随机)</param>
        public static byte[] BuildInnerPlaintext(DeviceProfile d, string? randB64 = null)
        {
            string adbStatus = d.AdbEnabled == 1 ? "running" : "stopped";
            string sysUsb = d.AdbEnabled == 1 ? "adb" : "mtp";
            string rand = randB64 ?? GenRand();

            var sb = new StringBuilder(1100);
            sb.Append('{');
            bool first = true;
            void S(string k, string v)
            {
                if (!first) sb.Append(',');
                first = false;
                sb.Append('"').Append(k).Append("\":\"").Append(InnerStr(v)).Append('"');
            }

            S("dynver", Extra03Baseline.Dynver);
            S("parallel", Extra03Baseline.Parallel);
            S("rootInfo", Extra03Baseline.RootInfoClean);
            S("rand", rand);
            S("adb_status", adbStatus);
            S("sys_usb_config", sysUsb);
            S("oem_unlock_supported", Extra03Baseline.OemUnlockSupported);
            S("oem_unlock_status", Extra03Baseline.OemUnlockStatus);
            S("verified_boot_state", Extra03Baseline.VerifiedBootState);
            S("model_sys_fingerprint", d.Fingerprint);
            S("cpu_abi", Extra03Baseline.CpuAbi);
            S("adb_enabled", d.AdbEnabled.ToString());
            S("wifi_adb_enabled", Extra03Baseline.WifiAdbEnabled);
            S("pts", Extra03Baseline.Pts);
            S("app_proc_access_size", Extra03Baseline.AppProcAccessSize);
            S("framwork_access_size", Extra03Baseline.FramworkAccessSize);
            S("frida_detect", Extra03Baseline.FridaDetect);
            S("debug_detect", Extra03Baseline.DebugDetect);
            S("repack_detect", Extra03Baseline.RepackDetect);
            S("seccomp_detect", Extra03Baseline.SeccompDetect);
            S("emulator_detect", Extra03Baseline.EmulatorDetect);
            S("hook_detect", Extra03Baseline.HookDetect);
            S("sepolicy_hash", Extra03Baseline.SepolicyHash);
            S("dedez", Extra03Baseline.Dedez);
            sb.Append('}');
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        // ==================== 外层 ====================

        /// <summary>
        /// 构造外层明文 JSON (6 字段)。s_f_d = 内层 {key,data} 包字符串。
        /// 外层用 org.json 风格转义 (转义 '/'), 复用 Extra02Builder.JsonStr。
        /// </summary>
        public static byte[] BuildOuterPlaintext(string pddid, string innerPackage)
        {
            var sb = new StringBuilder(innerPackage.Length + 128);
            sb.Append("{\"version\":1,")
              .Append("\"uid\":\"\",")
              .Append("\"app_name\":\"pdd\",")
              .Append("\"pddid\":\"").Append(Extra02Builder.JsonStr(pddid)).Append("\",")
              .Append("\"data_type\":20,")
              .Append("\"platform\":\"android\",")
              .Append("\"s_f_d\":\"").Append(Extra02Builder.JsonStr(innerPackage)).Append("\"}");
            return Encoding.UTF8.GetBytes(sb.ToString());
        }

        // ==================== rand 生成 ====================

        /// <summary>
        /// 生成 rand 字段: 容器头 (0f c1 00 00 04 04 00) + 10 字节随机 → base64。
        /// rand 是 arc4random 随机种子 (无语义, 服务端不校验内容), 每次不同, 格式贴合真机。
        /// </summary>
        public static string GenRand()
        {
            byte[] b = new byte[17];
            byte[] head = { 0x0f, 0xc1, 0x00, 0x00, 0x04, 0x04, 0x00 };
            Array.Copy(head, b, 7);
            byte[] rnd = new byte[10];
            RandomNumberGenerator.Fill(rnd);
            Array.Copy(rnd, 0, b, 7, 10);
            return Convert.ToBase64String(b);
        }

        // ==================== 内层 JSON 转义 (不转义 '/') ====================

        /// <summary>
        /// 内层检测 JSON 字符串转义: 转义 '"' '\' 和控制字符, **不转义 '/'** (实测真机如此)。
        /// </summary>
        public static string InnerStr(string s)
        {
            var sb = new StringBuilder(s.Length + 16);
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }
    }
}
