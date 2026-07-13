using System.Text.Json.Serialization;

namespace PddLib.Models
{
    /// <summary>
    /// GetRandomDeviceRecord 返回的单条事件记录。
    ///
    /// 一个设备 (x_utdid) 下有多条事件 (event_name), 每条 data 是该事件的数据 JSON 字符串。
    /// 拼多多 (type=5) 常见事件: 1000 / 1011 (随机设备必同时含这两个) 等。
    /// </summary>
    public class DeviceEventRecord
    {
        [JsonPropertyName("x_utdid")]
        public string XUtdid { get; set; } = string.Empty;

        [JsonPropertyName("event_name")]
        public string EventName { get; set; } = string.Empty;

        /// <summary>该事件的数据 (JSON 字符串)。</summary>
        [JsonPropertyName("data")]
        public string Data { get; set; } = string.Empty;
    }
}
