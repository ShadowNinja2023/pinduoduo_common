using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PddLib.Models;

namespace PddLib
{
    /// <summary>
    /// 自有后端 client 网关调用封装 (见 docs/client_api.md)。
    ///
    /// 统一入口 <c>/client</c>, 业务数据以 JSON 放在 <c>d</c> 参数, 公共参数:
    ///   c=方法名  d=业务JSON  a=apiKey  s=签名  ts=时间戳  (可选 t=令牌 g=分组)
    /// 签名: <c>s = MD5(ts + d + apiSecret).ToLower()</c> (d 为空时按空串参与)。
    /// 响应: <c>{ "State":1, "Data":..., "Message":"" }</c> (State==1 成功)。
    ///
    /// 本类用于设备记录库 (device_record), 目标接口 <see cref="GetRandomDeviceRecordAsync"/>。
    /// </summary>
    public class ClientApi
    {
        /// <summary>时间戳单位。</summary>
        public enum TsUnit { Seconds, Milliseconds }

        // ===== 设备库网关默认凭据 (client_api) =====
        public const string DefaultBaseUrl = "http://dsqclientcn.liuliang2024.com/client";
        public const string DefaultApiKey = "201902193423423535";
        public const string DefaultApiSecret = "cba0dda4d2fa4beaa17316890b22d646";

        /// <summary>用内置默认凭据创建 client 网关客户端。</summary>
        public static ClientApi Default() => new ClientApi(DefaultBaseUrl, DefaultApiKey, DefaultApiSecret);

        private readonly HttpClient _client;
        private readonly string _endpoint;   // 完整 /client 地址
        private readonly string _apiKey;
        private readonly string _apiSecret;
        private readonly string? _token;
        private readonly string? _group;
        private readonly TsUnit _tsUnit;

        private static readonly JsonSerializerOptions JsonOptions = new()
        {
            PropertyNameCaseInsensitive = true
        };

        /// <param name="baseUrl">网关地址 (含或不含 /client 均可), 如 https://open.example.com</param>
        /// <param name="apiKey">API 密钥 (a 参数)</param>
        /// <param name="apiSecret">签名密钥 (仅参与 MD5, 不上送)</param>
        /// <param name="token">可选令牌 (t 参数)</param>
        /// <param name="group">可选分组 (g 参数)</param>
        /// <param name="tsUnit">时间戳单位, 默认秒 (实测服务端按秒校验; 如需毫秒传 Milliseconds)</param>
        public ClientApi(string baseUrl, string apiKey, string apiSecret,
            string? token = null, string? group = null, TsUnit tsUnit = TsUnit.Seconds)
        {
            string b = baseUrl.TrimEnd('/');
            _endpoint = b.EndsWith("/client", StringComparison.OrdinalIgnoreCase) ? b : b + "/client";
            _apiKey = apiKey;
            _apiSecret = apiSecret;
            _token = token;
            _group = group;
            _tsUnit = tsUnit;
            _client = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        }

        /// <summary>MD5(s) 小写十六进制。</summary>
        public static string Md5Lower(string s)
        {
            byte[] hash = MD5.HashData(Encoding.UTF8.GetBytes(s));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        private string NowTs() => (_tsUnit == TsUnit.Seconds
            ? DateTimeOffset.UtcNow.ToUnixTimeSeconds()
            : DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).ToString();

        /// <summary>
        /// 调用一个方法 (POST form), 返回原始响应体字符串。
        /// </summary>
        /// <param name="method">c: 方法名</param>
        /// <param name="dataJson">d: 业务数据 JSON; 无参接口传 null/空</param>
        public async Task<string> CallRawAsync(string method, string? dataJson = null)
        {
            string data = dataJson ?? "";
            string ts = NowTs();
            string sign = Md5Lower(ts + data + _apiSecret);

            var form = new List<KeyValuePair<string, string>>
            {
                new("c", method),
                new("d", data),
                new("a", _apiKey),
                new("s", sign),
                new("ts", ts),
            };
            if (!string.IsNullOrEmpty(_token)) form.Add(new("t", _token));
            if (!string.IsNullOrEmpty(_group)) form.Add(new("g", _group));

            using var content = new FormUrlEncodedContent(form);
            var resp = await _client.PostAsync(_endpoint, content);
            return await resp.Content.ReadAsStringAsync();
        }

        /// <summary>调用一个方法并按 <see cref="ClientApiResponse{T}"/> 反序列化。</summary>
        public async Task<ClientApiResponse<T>> CallAsync<T>(string method, string? dataJson = null)
        {
            string body = await CallRawAsync(method, dataJson);
            return JsonSerializer.Deserialize<ClientApiResponse<T>>(body, JsonOptions)
                   ?? throw new InvalidOperationException("client 网关响应反序列化失败: " + body);
        }

        /// <summary>
        /// 随机获取一个同时含事件 1000 与 1011 的设备, 返回其全部事件记录。
        /// 无需传参; 每次调用随机返回不同设备。列表为空表示库里没有满足条件的设备。
        /// </summary>
        public async Task<RandomDeviceRecord> GetRandomDeviceRecordAsync()
        {
            var resp = await CallAsync<List<DeviceEventRecord>>("GetRandomDeviceRecord");
            if (!resp.IsSuccess)
                throw new InvalidOperationException($"GetRandomDeviceRecord 失败: State={resp.State} Message={resp.Message}");
            return new RandomDeviceRecord(resp.Data ?? new List<DeviceEventRecord>());
        }

        /// <summary>
        /// 便捷: 随机取一台淘宝设备并解码 1011 event body 为 <see cref="PddLib.Register.TaobaoDeviceRecord"/>
        /// (供转换器/mocker 直接使用)。无 1011 event 时抛异常。
        /// </summary>
        public async Task<PddLib.Register.TaobaoDeviceRecord> GetRandomTaobaoDeviceAsync()
        {
            var rec = await GetRandomDeviceRecordAsync();
            string? d1011 = rec.Event1011;
            if (string.IsNullOrEmpty(d1011))
                throw new InvalidOperationException("随机设备无 1011 event, 无法转换");
            string body = d1011!;
            try
            {
                using var doc = JsonDocument.Parse(d1011!);
                if (doc.RootElement.TryGetProperty("body", out var b)) body = b.GetString() ?? d1011!;
            }
            catch { /* d1011 本身即 body */ }

            var (_, items) = PddLib.Crypto.Taobao.RepedCrypto.Decode(body);
            return new PddLib.Register.TaobaoDeviceRecord(items, rec.XUtdid);
        }
    }

    /// <summary>
    /// 一个随机设备的全部事件记录 (GetRandomDeviceRecord 结果封装)。
    /// 按 event_name 索引取各事件 data。
    /// </summary>
    public class RandomDeviceRecord
    {
        public string XUtdid { get; }
        public IReadOnlyList<DeviceEventRecord> Events { get; }

        public RandomDeviceRecord(List<DeviceEventRecord> events)
        {
            Events = events;
            XUtdid = events.Count > 0 ? events[0].XUtdid : "";
        }

        public bool IsEmpty => Events.Count == 0;

        /// <summary>取指定事件的 data (JSON 字符串); 不存在返回 null。</summary>
        public string? GetEventData(string eventName)
        {
            foreach (var e in Events)
                if (e.EventName == eventName) return e.Data;
            return null;
        }

        /// <summary>event 1000 的数据 (通常是设备基础上报载荷)。</summary>
        public string? Event1000 => GetEventData("1000");

        /// <summary>event 1011 的数据。</summary>
        public string? Event1011 => GetEventData("1011");
    }
}
