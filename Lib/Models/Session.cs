using System.Text.Json.Serialization;

namespace PddLib.Models
{
    /// <summary>
    /// 用户会话信息（对应 GetDevice 返回的 info）
    /// </summary>
    public class Session
    {
        [JsonPropertyName("uid")]
        public long Uid { get; set; }

        [JsonPropertyName("uin")]
        public string Uin { get; set; } = string.Empty;

        [JsonPropertyName("acid")]
        public string Acid { get; set; } = string.Empty;

        [JsonPropertyName("mobile_id")]
        public string MobileId { get; set; } = string.Empty;

        [JsonPropertyName("mobile_des")]
        public string MobileDes { get; set; } = string.Empty;

        [JsonPropertyName("access_token")]
        public string AccessToken { get; set; } = string.Empty;
    }
}
