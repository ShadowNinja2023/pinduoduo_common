using System.Text.Json.Serialization;

namespace PddLib.Models
{
    /// <summary>
    /// 统一响应结构
    /// </summary>
    public class ApiResponse<T>
    {
        [JsonPropertyName("code")]
        public string Code { get; set; } = string.Empty;

        [JsonPropertyName("messages")]
        public string Messages { get; set; } = string.Empty;

        [JsonPropertyName("results")]
        public T? Results { get; set; }

        /// <summary>是否成功 (code == "100")</summary>
        [JsonIgnore]
        public bool IsSuccess => Code == "100";
    }

    /// <summary>
    /// 无 results 的响应
    /// </summary>
    public class ApiResponse : ApiResponse<object> { }
}
