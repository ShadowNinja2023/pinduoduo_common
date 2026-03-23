using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;

namespace PddLib
{
    /// <summary>
    /// HTTP 响应结果
    /// </summary>
    public class HttpResult
    {
        public string Body { get; set; } = string.Empty;
        public HttpResponseHeaders Headers { get; set; } = null!;
        public HttpStatusCode StatusCode { get; set; }
    }

    /// <summary>
    /// 基础 HTTP 通信封装
    /// </summary>
    public class Http
    {
        private HttpClient _client;

        public Http(string? proxyUrl = null)
        {
            _client = CreateClient(proxyUrl);
        }

        public void SetProxy(string? proxyUrl)
        {
            _client.Dispose();
            _client = CreateClient(proxyUrl);
        }

        private static HttpClient CreateClient(string? proxyUrl)
        {
            if (string.IsNullOrEmpty(proxyUrl))
                return new HttpClient();

            var proxy = CreateWebProxy(proxyUrl);
            var handler = new HttpClientHandler
            {
                Proxy = proxy,
                UseProxy = true,
                UseDefaultCredentials = false,
                PreAuthenticate = true
            };
            return new HttpClient(handler);
        }

        /// <summary>
        /// 创建 WebProxy，正确处理带认证信息的代理 URL
        /// </summary>
        private static WebProxy CreateWebProxy(string proxyUrl)
        {
            var uri = new Uri(proxyUrl);
            
            // 构建不带认证信息的代理地址
            var proxyAddress = new Uri($"{uri.Scheme}://{uri.Host}:{uri.Port}");
            var proxy = new WebProxy(proxyAddress);

            // 如果 URL 包含用户名和密码
            if (!string.IsNullOrEmpty(uri.UserInfo))
            {
                var userInfo = uri.UserInfo;
                var colonIndex = userInfo.IndexOf(':');
                if (colonIndex > 0)
                {
                    // URL 解码用户名和密码
                    var username = Uri.UnescapeDataString(userInfo.Substring(0, colonIndex));
                    var password = Uri.UnescapeDataString(userInfo.Substring(colonIndex + 1));
                    proxy.Credentials = new NetworkCredential(username, password);
                }
                else
                {
                    proxy.Credentials = new NetworkCredential(Uri.UnescapeDataString(userInfo), string.Empty);
                }
            }

            return proxy;
        }

        /// <summary>
        /// 发送 POST 请求，返回 body 字符串
        /// </summary>
        public async Task<string> PostAsync(string url, object body, Dictionary<string, string>? headers = null)
        {
            var result = await PostFullAsync(url, body, headers);
            return result.Body;
        }

        /// <summary>
        /// 发送 POST 请求，返回完整响应（含 headers）
        /// </summary>
        public async Task<HttpResult> PostFullAsync(string url, object body, Dictionary<string, string>? headers = null)
        {
            var json = JsonSerializer.Serialize(body);
            var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
            };

            if (headers != null)
            {
                foreach (var kv in headers)
                    request.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
            }

            var response = await _client.SendAsync(request);
            response.EnsureSuccessStatusCode();

            return new HttpResult
            {
                Body = await response.Content.ReadAsStringAsync(),
                Headers = response.Headers,
                StatusCode = response.StatusCode
            };
        }
    }
}
