using System.Text.Json;
using System.Text.Json.Serialization;

namespace PddLib.Models
{
    /// <summary>
    /// GetDevice 响应 results
    /// </summary>
    public class GetDeviceResult
    {
        [JsonPropertyName("account")]
        public string Account { get; set; } = string.Empty;

        [JsonPropertyName("info")]
        public string Info { get; set; } = string.Empty;

        [JsonPropertyName("device")]
        public string Device { get; set; } = string.Empty;

        /// <summary>解析 Info 为 Session 对象</summary>
        public Session ParseSession()
        {
            return JsonSerializer.Deserialize<Session>(Info)
                   ?? throw new InvalidOperationException("Session 解析失败");
        }

        /// <summary>解析 Device 为 Device 对象</summary>
        public Device ParseDevice()
        {
            return JsonSerializer.Deserialize<Device>(Device)
                   ?? throw new InvalidOperationException("Device 解析失败");
        }
    }
}
