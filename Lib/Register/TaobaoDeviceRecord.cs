using System;
using System.Collections.Generic;
using System.Linq;
using PddLib.Crypto.Taobao;

namespace PddLib.Register
{
    /// <summary>
    /// 一台淘宝(SGMain/reped)设备解码后的检测项集合, 按 detect_id / detect:policy 建索引。
    ///
    /// 数据来自 <see cref="RepedCrypto.Decode"/> 的第二个返回值 (List&lt;DetectItem&gt;),
    /// 检测项语义见 SGMain VMProtect学习/sgmain_full_analysis/docs/DETECT_ITEMS_CATALOG.md。
    /// TEA 二次加密项 (enc=Tea) 已由 RepedCrypto 解出明文, 直接读 Value。
    /// </summary>
    public class TaobaoDeviceRecord
    {
        private readonly Dictionary<string, string> _byDetect = new();       // detect_id → value (首个)
        private readonly Dictionary<string, string> _byDetectPolicy = new();  // "detect:policy" → value

        public string XUtdid { get; set; } = "";
        public IReadOnlyList<DetectItem> Items { get; }

        public TaobaoDeviceRecord(IEnumerable<DetectItem> items, string xUtdid = "")
        {
            Items = items.ToList();
            XUtdid = xUtdid;
            foreach (var it in Items)
            {
                if (string.IsNullOrEmpty(it.DetectId)) continue;
                string v = it.Value ?? (it.BinaryValue != null ? Convert.ToHexString(it.BinaryValue) : "");
                _byDetectPolicy[$"{it.DetectId}:{it.PolicyId}"] = v;
                if (!_byDetect.ContainsKey(it.DetectId)) _byDetect[it.DetectId] = v;  // 首个命中
            }
        }

        /// <summary>按 detect_id 取值 (同 id 多 policy 时返回首个)。不存在返回 null。</summary>
        public string? Get(string detect)
            => _byDetect.TryGetValue(detect, out var v) ? v : null;

        /// <summary>按 detect_id + policy_id 精确取值。不存在返回 null。</summary>
        public string? Get(string detect, string policy)
            => _byDetectPolicy.TryGetValue($"{detect}:{policy}", out var v) ? v : null;

        /// <summary>存在任一 policy 的该 detect_id。</summary>
        public bool Has(string detect) => _byDetect.ContainsKey(detect);
    }
}
