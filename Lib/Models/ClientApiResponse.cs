using System.Text.Json.Serialization;

namespace PddLib.Models
{
    /// <summary>
    /// client_api.md 网关统一响应结构: { "State": 1, "Data": {...}, "Message": "" }。
    /// 实测服务端用短键 S/M/D。
    /// </summary>
    public class ClientApiResponse<T>
    {
        // ⚠ 实测服务端用短键 S/M/D (文档写的 State/Data/Message 是别名, 实际不返回)。
        [JsonPropertyName("S")]
        public int State { get; set; }

        [JsonPropertyName("D")]
        public T? Data { get; set; }

        [JsonPropertyName("M")]
        public string Message { get; set; } = string.Empty;

        /// <summary>是否成功 (S == 1)。</summary>
        [JsonIgnore]
        public bool IsSuccess => State == 1;
    }
}
