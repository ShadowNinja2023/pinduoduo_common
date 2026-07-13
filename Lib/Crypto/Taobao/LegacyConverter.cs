using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib.Crypto.Taobao
{
    internal static class LegacyConverter
    {
        private const string Marker = "[<^@??@^>]";
        private static readonly byte[] VigKeyFixed = { 0x2A, 0x25, 0x24, 0x23, 0x40 }; // *%$#@

        // ═══════════════════════════════════════════════════════════
        // 新版本目标值
        // ═══════════════════════════════════════════════════════════
        private const string NewBa2eValue = "127";
        private const string New71f3Value = "46";
        private const string New99b3Value = "56";
        private const string NewSdkVersion = "6.7.260202";
        private const string NewApkVersion = "10.59.30";
        private const string New9353Value = "6.7.260202;6.7.260202;6.7.260202";

        // 正版淘宝 APK 签名 SHA1
        private const string CorrectApkSignature = "3e596b95df57df7ed20cd376fdb077fca426f873";
        // 正版应用名
        private const string CorrectAppLabel = "淘宝";

        // 旧版本独有、新版本不存在的 detect_id (应删除)
        private static readonly HashSet<string> DeleteDetectIds = new HashSet<string>
        {
            // ★★★ 第三步: 删除旧版独有字段 (8 项)
            "eb79_cecf",   // KeyStore 异常 (改包导致)
            "6d03_5e07",   // 旧版 RIL 版本 property
            "f57c_b151",   // 旧版策略组 (新版已移除, f57c:5468 保留)
            "25c8_cecf",   // 旧版独有标识
            "6b3a_b151",   // 旧版传感器 hash
            "95ee_cecf",   // 旧版独有标识
            "6704_bb98",   // 旧版 bb98 标志位
            "2a64_44c7",   // 旧版 SDK token 格式 (被 9785:44c7 替代)
        };

        // 手机特有字段 — 如果旧数据是云手机/虚拟设备, 这些字段也应删除
        // 但如果是真实手机则保留, 由 convertOptions 控制
        private static readonly HashSet<string> PhoneOnlyFields = new HashSet<string>
        {
            "095a_cecf",   // 运营商名
            "f02e_cecf",   // 运营商代码
            "9782_5e07",   // SIM 卡状态
            "caba_7326",   // 电话网络 JSON
            "17ed_5e07",   // 基带版本
            "cdb2_cecf",   // 设备 ID/IMEI
            "082b_cecf",   // Binder 标识
            "e064_cecf",   // SoterService
        };

        // Encoder 自动生成的 slot (不需要手动加入)
        private static readonly HashSet<string> EncoderAutoSlots = new HashSet<string>
        {
            "bd30_0cb5",
            "45b7_0cb5",
        };

        // 613d 新版本位数要求 (detect_id → 需要的总位数)
        private static readonly Dictionary<string, int> Fingerprint613dNewLengths = new Dictionary<string, int>
        {
            { "273e", 13 },   // 旧版 "err|..." → 新版 13 位
            { "351f", 21 },   // 旧版 19 位 → 新版 21 位
            { "6f60", 44 },   // 旧版 28 位 → 新版 44 位
        };

        /// <summary>
        /// 转换选项
        /// </summary>
        public class ConvertOptions
        {
            /// <summary>是否删除手机特有字段 (旧数据是云手机时设为 true)</summary>
            public bool RemovePhoneOnlyFields { get; set; } = false;

            /// <summary>是否 patch c662 Key Attestation (方案 B: 替换 versionCode + signatureDigest 为正版值)</summary>
            public bool PatchC662Digest { get; set; } = true;

            /// <summary>新版 SDK 版本号</summary>
            public string SdkVersion { get; set; } = NewSdkVersion;

            /// <summary>新版 APK 版本号</summary>
            public string ApkVersion { get; set; } = NewApkVersion;

            /// <summary>9785:44c7 是否跳过 Vigenere (新版行为)</summary>
            public bool SkipVigenere9785 { get; set; } = true;
        }

        /// <summary>
        /// 从旧版本 JSON 转换为 DetectItem 列表 (完整升级)
        /// </summary>
        /// <param name="jsonItems">旧版本 JSON 解析后的 Key/Value 列表</param>
        /// <param name="options">转换选项 (可选)</param>
        /// <returns>可直接传入 EsEncoder.Encode 的检测项列表</returns>
        public static List<DetectItem> Convert(
            List<LegacyItem> jsonItems,
            ConvertOptions options = null)
        {
            if (options == null) options = new ConvertOptions();

            // 步骤 1: 构建 key→value 字典
            var rawItems = new Dictionary<string, string>();
            foreach (var item in jsonItems)
            {
                if (string.IsNullOrEmpty(item.Key)) continue;
                rawItems[item.Key] = item.Value ?? "";
            }

            // 步骤 2: 提取 Vigenere key (从 45b7_0cb5 用固定 key 解码)
            byte[] vigKey = ExtractVigenereKey(rawItems);

            // 步骤 3: Vigenere 解码所有带 marker 的项
            var decoded = new Dictionary<string, string>();
            foreach (var kv in rawItems)
            {
                string k = kv.Key;
                string v = kv.Value;

                if (!IsStandardKey(k)) continue;

                if (v.StartsWith(Marker))
                {
                    string raw = v.Substring(Marker.Length);
                    // ★ legacy JSON 为 UTF-8 存储, 含中文 (如 "淘宝") 的 Value 被反序列化成
                    //   多字节 Unicode 字符。Vigenere 输出恒在 0x20~0x7e, 唯一的非 ASCII
                    //   是透传的中文 UTF-8 序列, 故整串是合法 UTF-8。必须用 UTF-8 还原密文字节,
                    //   否则 latin1 会把 "淘宝"(6字节) 压成 2 个 '?', 导致 key 索引错位 + 尾部乱码。
                    byte[] rawBytes = Encoding.UTF8.GetBytes(raw);
                    byte[] dec = VigenereCipher.Decrypt(rawBytes, vigKey);
                    decoded[k] = Encoding.GetEncoding("latin1").GetString(dec);
                }
                else
                {
                    decoded[k] = v;
                }
            }

            // 步骤 4: TEA 二次解密 (TEA_ENC_KEYS 集合)
            var teaDecrypted = new Dictionary<string, string>();
            foreach (var kv in decoded)
            {
                string k = kv.Key;
                string v = kv.Value;

                if (TeaXtea.TeaEncKeys.Contains(k))
                {
                    byte[] plain = TeaXtea.TeaXteaDecrypt(
                        Encoding.GetEncoding("latin1").GetBytes(v),
                        k.Split('_')[0], k.Split('_')[1]);
                    if (plain != null && plain.Length > 0)
                    {
                        teaDecrypted[k] = Encoding.GetEncoding("latin1").GetString(plain);
                    }
                }
            }

            // 步骤 5: 构造 DetectItem 列表 + 升级转换
            var result = new List<DetectItem>();

            // 构建删除集合
            var skipIds = new HashSet<string>(EncoderAutoSlots);
            skipIds.UnionWith(DeleteDetectIds);
            if (options.RemovePhoneOnlyFields)
                skipIds.UnionWith(PhoneOnlyFields);

            foreach (var kv in decoded)
            {
                string k = kv.Key;
                if (skipIds.Contains(k)) continue;

                string did = k.Split('_')[0];
                string pid = k.Split('_')[1];
                string value = kv.Value;
                bool skipVig = false;
                var secEnc = SecondaryEncType.None;

                // ═══════════════════════════════════════════════
                // 判断二次加密类型
                // ═══════════════════════════════════════════════
                if (TeaXtea.TeaEncKeys.Contains(k))
                {
                    if (teaDecrypted.ContainsKey(k))
                        value = teaDecrypted[k];
                    secEnc = SecondaryEncType.Tea;
                }
                else if (k == TeaXtea.E0a1B1b2Key)
                {
                    secEnc = SecondaryEncType.None; // 透传
                }
                else if (TeaXtea.Bb98CrossTea.ContainsKey(k))
                {
                    secEnc = SecondaryEncType.None; // 透传 (bb98 TEA 参数可能不同)
                }

                // 9785_44c7 在新版本中有 marker (非 skip)
                if (k == "9785_44c7" && !options.SkipVigenere9785)
                {
                    skipVig = false;
                }

                result.Add(new DetectItem
                {
                    DetectId = did,
                    PolicyId = pid,
                    Value = value,
                    SkipVigenere = skipVig,
                    SecondaryEnc = secEnc
                });
            }

            // ═══════════════════════════════════════════════════════════
            // ★★★ 第四步: 补充新版通用字段 (6 项, 72b0 除外)
            // ═══════════════════════════════════════════════════════════
            AppendNewVersionFields(result, decoded);

            return result;
        }

        /// <summary>
        /// 兼容旧版调用的简化接口
        /// </summary>
        public static List<DetectItem> Convert(
            List<LegacyItem> jsonItems,
            string newSdkVersion)
        {
            return Convert(jsonItems, new ConvertOptions { SdkVersion = newSdkVersion ?? NewSdkVersion });
        }

        // ═══════════════════════════════════════════════════════════
        // 613d 品牌指纹升级
        // ═══════════════════════════════════════════════════════════

        /// <summary>
        /// 升级 613d 字段: "1|数字序列" → "3|数字序列" + 位数补齐
        /// 273e 特殊: "err|config value is null!" → "3|13位全奇数"
        /// </summary>
        private static string Upgrade613d(string detectId, string value)
        {
            // 273e 特殊处理: 旧版 "err|..." → 新版 "3|13位全奇数"
            if (detectId == "273e" && value.StartsWith("err|"))
            {
                int targetLen = Fingerprint613dNewLengths.TryGetValue("273e", out int n) ? n : 13;
                return "3|" + GenerateOddDigits(targetLen);
            }

            if (!value.StartsWith("1|")) return value;
            string digits = value.Substring(2);

            // 位数补齐: 特定 detect_id 需要增加到指定长度
            if (Fingerprint613dNewLengths.TryGetValue(detectId, out int targetLength))
            {
                if (digits.Length < targetLength)
                {
                    // 末尾补奇数
                    int needed = targetLength - digits.Length;
                    digits += GenerateOddDigits(needed);
                }
            }

            return "3|" + digits;
        }

        /// <summary>生成指定长度的奇数数字序列 (1,3,5,7,9 随机)</summary>
        private static string GenerateOddDigits(int count)
        {
            var sb = new StringBuilder(count);
            var rng = new Random();
            int[] odds = { 1, 3, 5, 7, 9 };
            for (int i = 0; i < count; i++)
                sb.Append(odds[rng.Next(odds.Length)]);
            return sb.ToString();
        }

        // ═══════════════════════════════════════════════════════════
        // 9785:44c7 精简
        // ═══════════════════════════════════════════════════════════

        /// <summary>
        /// 精简 9785:44c7 — 只保留 com.taobao.taobao + gs.fs.id
        /// </summary>
        private static string Simplify9785Token(string value)
        {
            if (string.IsNullOrEmpty(value)) return value;

            // 尝试从旧格式中提取 gs.fs.id 和 com.taobao.taobao 的值
            string gsToken = ExtractJsonField(value, "gs.fs.id", "v");
            string tbToken = ExtractJsonField(value, "com.taobao.taobao", "v");

            if (string.IsNullOrEmpty(gsToken) || string.IsNullOrEmpty(tbToken))
                return value; // 无法解析时保留原值

            // 构建精简格式 (新版只需要这两个)
            return "{\"version\":2,\"data\":{\"gs.fs.id\":[{\"v\":\"" + gsToken +
                   "\",\"s\":64,\"c\":2}],\"com.taobao.taobao\":[{\"v\":\"" + tbToken +
                   "\",\"s\":128,\"c\":2}]}}";
        }

        /// <summary>从嵌套 JSON 中提取指定 key 内的 field 值 (简单正则)</summary>
        private static string ExtractJsonField(string json, string outerKey, string innerKey)
        {
            // 匹配 "outerKey" : [{ "innerKey" : "value" ... }]
            // 或 "outerKey": [{"innerKey":"value"...}]
            int idx = json.IndexOf("\"" + outerKey + "\"");
            if (idx < 0) return null;

            // 从 outerKey 位置往后找 innerKey 的值
            string sub = json.Substring(idx);
            var m = System.Text.RegularExpressions.Regex.Match(sub,
                "\"" + System.Text.RegularExpressions.Regex.Escape(innerKey) + "\"\\s*:\\s*\"([^\"]+)\"");
            return m.Success ? m.Groups[1].Value : null;
        }

        // ═══════════════════════════════════════════════════════════
        // 43b2:bb98 同步 ba2e
        // ═══════════════════════════════════════════════════════════

        /// <summary>
        /// 同步 43b2:bb98 的第3字段为新版 ba2e 值
        /// 格式: "品牌,SDK版本,ba2e值,时间戳"
        /// </summary>
        private static string Sync43b2Ba2e(string value, string newBa2e)
        {
            if (string.IsNullOrEmpty(value)) return value;
            var parts = value.Split(',');
            if (parts.Length >= 4)
            {
                parts[2] = newBa2e; // 第3字段 = ba2e 值
                return string.Join(",", parts);
            }
            return value;
        }

        // ═══════════════════════════════════════════════════════════
        // 补充新版通用字段
        // ═══════════════════════════════════════════════════════════

        /// <summary>
        /// 补充新版本必须的通用字段 (如果原数据中不存在)
        /// </summary>
        private static void AppendNewVersionFields(List<DetectItem> result, Dictionary<string, string> decoded)
        {
            var existing = new HashSet<string>(result.Select(r => $"{r.DetectId}_{r.PolicyId}"));

            // c07a:cecf = 随机 UUID (GAID)
            if (!existing.Contains("c07a_cecf") && !decoded.ContainsKey("c07a_cecf"))
            {
                result.Add(new DetectItem
                {
                    DetectId = "c07a",
                    PolicyId = "cecf",
                    Value = Guid.NewGuid().ToString(),
                    SkipVigenere = false,
                    SecondaryEnc = SecondaryEncType.None
                });
            }

            // d752:cecf = {"l":""}
            if (!existing.Contains("d752_cecf") && !decoded.ContainsKey("d752_cecf"))
            {
                result.Add(new DetectItem
                {
                    DetectId = "d752",
                    PolicyId = "cecf",
                    Value = "{\"l\":\"\"}",
                    SkipVigenere = false,
                    SecondaryEnc = SecondaryEncType.None
                });
            }

            // 133f:17f2 = "{ }"
            if (!existing.Contains("133f_17f2") && !decoded.ContainsKey("133f_17f2"))
            {
                result.Add(new DetectItem
                {
                    DetectId = "133f",
                    PolicyId = "17f2",
                    Value = "{ }",
                    SkipVigenere = false,
                    SecondaryEnc = SecondaryEncType.None
                });
            }

            // 0fa0:bb98 = 0
            if (!existing.Contains("0fa0_bb98") && !decoded.ContainsKey("0fa0_bb98"))
            {
                result.Add(new DetectItem
                {
                    DetectId = "0fa0",
                    PolicyId = "bb98",
                    Value = "0",
                    SkipVigenere = false,
                    SecondaryEnc = SecondaryEncType.None
                });
            }

            // 4285:bb98 = 0
            if (!existing.Contains("4285_bb98") && !decoded.ContainsKey("4285_bb98"))
            {
                result.Add(new DetectItem
                {
                    DetectId = "4285",
                    PolicyId = "bb98",
                    Value = "0",
                    SkipVigenere = false,
                    SecondaryEnc = SecondaryEncType.None
                });
            }

            // 7d6a:bb98 = 0
            if (!existing.Contains("7d6a_bb98") && !decoded.ContainsKey("7d6a_bb98"))
            {
                result.Add(new DetectItem
                {
                    DetectId = "7d6a",
                    PolicyId = "bb98",
                    Value = "0",
                    SkipVigenere = false,
                    SecondaryEnc = SecondaryEncType.None
                });
            }

            // ★ 72b0:b151 (传感器完整列表) — 需要从目标设备提取, 暂不自动补充
        }

        // ═══════════════════════════════════════════════════════════
        // 辅助方法
        // ═══════════════════════════════════════════════════════════

        /// <summary>
        /// 从 45b7_0cb5 提取 Vigenere key
        /// </summary>
        private static byte[] ExtractVigenereKey(Dictionary<string, string> items)
        {
            string raw0cb5;
            if (!items.TryGetValue("45b7_0cb5", out raw0cb5) || !raw0cb5.StartsWith(Marker))
                throw new InvalidOperationException("缺少 45b7_0cb5 或格式不正确");

            string stripped = raw0cb5.Substring(Marker.Length);
            byte[] rawBytes = Encoding.GetEncoding("latin1").GetBytes(stripped);
            byte[] decoded = VigenereCipher.Decrypt(rawBytes, VigKeyFixed);

            if (decoded.Length < 8)
                throw new InvalidOperationException($"0cb5 解码后长度不足: {decoded.Length}");

            byte[] key = new byte[8];
            Array.Copy(decoded, decoded.Length - 8, key, 0, 8);
            return key;
        }

        /// <summary>判断是否是标准 detect_id_policy_id 格式的 key</summary>
        private static bool IsStandardKey(string key)
        {
            if (string.IsNullOrEmpty(key) || !key.Contains('_')) return false;
            string[] parts = key.Split('_');
            return parts[0].Length == 4 && parts.Length == 2;
        }
    }

    /// <summary>旧版本 JSON 中的单个检测项</summary>
    public class LegacyItem
    {
        public string Key { get; set; }
        public string Value { get; set; }
    }
}
