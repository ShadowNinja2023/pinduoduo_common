using Newtonsoft.Json;
using System.Net;
using System.Net.Http.Headers;
using System.Text.Encodings.Web;
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
        /// <summary>
        /// body 序列化选项: 用宽松编码器, 避免默认 JavaScriptEncoder 把 +、非 ASCII(中文) 等
        /// 转成 \uXXXX (与真机请求字节级对齐, 如 csr_risk_token 里的 '+')。
        /// </summary>
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };

        private HttpClient _client;
        private string? _proxyUrl;
        private string? _proxyUsername;
        private string? _proxyPassword;
        public HttpClientHandler handler;

        /// <summary>共享 cookie 容器 (可由外部传入, 与注册客户端共用以自动管理 api_uid 等)。</summary>
        public CookieContainer Cookies { get; }

        public Http(string? proxyUrl = null, string? proxyUsername = null, string? proxyPassword = null,
            CookieContainer? cookieContainer = null)
        {
            _proxyUrl = proxyUrl;
            _proxyUsername = proxyUsername;
            _proxyPassword = proxyPassword;
            Cookies = cookieContainer ?? new CookieContainer();
            var created = CreateClient(proxyUrl, proxyUsername, proxyPassword, Cookies);
            _client = created.client;
            handler = created.handler;
        }

        public void SetProxy(string? proxyUrl, string? proxyUsername = null, string? proxyPassword = null)
        {
            _client.Dispose();
            _proxyUrl = proxyUrl;
            _proxyUsername = proxyUsername;
            _proxyPassword = proxyPassword;
            var created = CreateClient(proxyUrl, proxyUsername, proxyPassword, Cookies);
            _client = created.client;
            handler = created.handler;
        }

        private static (HttpClient client, HttpClientHandler handler) CreateClient(
            string? proxyUrl, string? proxyUsername, string? proxyPassword, CookieContainer cookies)
        {
            var handler = new HttpClientHandler
            {
                AutomaticDecompression = System.Net.DecompressionMethods.All,
                CookieContainer = cookies,
                UseCookies = true,
            };

            if (!string.IsNullOrEmpty(proxyUrl))
            {
                var proxy = new WebProxy(proxyUrl);
                if (!string.IsNullOrEmpty(proxyUsername))
                    proxy.Credentials = new NetworkCredential(proxyUsername, proxyPassword ?? string.Empty);

                handler.Proxy = proxy;
                handler.UseProxy = true;
            }

            var client = new HttpClient(handler)
            {
                DefaultRequestVersion = new Version(2, 0),
                DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher
            };

            return (client, handler);
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
            var json = JsonConvert.SerializeObject(body);
            return await PostRawAsync(url, json, headers);
        }

        /// <summary>
        /// 发送 POST 请求，body 为已序列化好的原始 JSON 字符串 (逐字节原样发送)。
        /// 用于需要 body 与签名 (如 x-p1) 完全自洽的接口。
        /// </summary>
        public async Task<HttpResult> PostRawAsync(string url, string json, Dictionary<string, string>? headers = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, url)
            {
                Content = new StringContent(json, System.Text.Encoding.UTF8, "application/json")
            };
            request.Content.Headers.Remove("Content-Type");
            request.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json;charset=UTF-8");

            if (headers != null)
            {
                foreach (var kv in headers)
                    request.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
            }

            var response = await _client.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            return new HttpResult
            {
                Body = responseBody,
                Headers = response.Headers,
                StatusCode = response.StatusCode
            };
        }

        /// <summary>
        /// 发送 GET 请求，返回 body 字符串。
        /// </summary>
        public async Task<string> GetAsync(string url, Dictionary<string, string>? headers = null)
            => (await GetFullAsync(url, headers)).Body;

        /// <summary>
        /// 发送 GET 请求，返回完整响应（含 headers）。
        /// 用于打开中转 H5 页 (goods.html 等)，让服务端记录会话内的页面访问。
        /// </summary>
        public async Task<HttpResult> GetFullAsync(string url, Dictionary<string, string>? headers = null)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, url);

            if (headers != null)
            {
                foreach (var kv in headers)
                    request.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
            }

            var response = await _client.SendAsync(request);
            var responseBody = await response.Content.ReadAsStringAsync();

            return new HttpResult
            {
                Body = responseBody,
                Headers = response.Headers,
                StatusCode = response.StatusCode
            };
        }
    }
}
