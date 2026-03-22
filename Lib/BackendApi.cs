using System.Text.Json;
using PddLib.Models;

namespace PddLib
{
    /// <summary>
    /// 自有后端 API 调用封装
    /// </summary>
    public class BackendApi
    {
        private readonly HttpClient _client;
        private readonly string _baseUrl;
        private readonly string _token;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true
        };

        /// <param name="baseUrl">后端地址，如 https://open-cdn.reverse-studio.com</param>
        /// <param name="token">鉴权令牌</param>
        public BackendApi(string baseUrl, string token)
        {
            _baseUrl = baseUrl.TrimEnd('/');
            _token = token;
            _client = new HttpClient();
        }

        /// <summary>
        /// 基础请求方法：POST JSON 并反序列化为统一响应
        /// </summary>
        private async Task<ApiResponse<T>> PostAsync<T>(string service, string method, object? body = null)
        {
            var url = $"{_baseUrl}/{service}/{method}?Token={Uri.EscapeDataString(_token)}";
            var json = body != null ? JsonSerializer.Serialize(body) : "{}";
            var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

            var response = await _client.PostAsync(url, content);
            response.EnsureSuccessStatusCode();

            var responseJson = await response.Content.ReadAsStringAsync();
            return JsonSerializer.Deserialize<ApiResponse<T>>(responseJson, JsonOptions)
                   ?? throw new InvalidOperationException("响应反序列化失败");
        }

        /// <summary>
        /// 获取拼多多设备信息
        /// </summary>
        /// <param name="account">账号，为空则随机返回一个设备</param>
        public async Task<ApiResponse<GetDeviceResult>> GetDeviceAsync(string? account = null)
        {
            var body = string.IsNullOrEmpty(account)
                ? new { }
                : (object)new { account };

            return await PostAsync<GetDeviceResult>("PinDuoDuo", "GetDevice", body);
        }
    }
}
