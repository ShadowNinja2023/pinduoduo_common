using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using PddLib.Crypto;

namespace PddLib.Register
{
    /// <summary>
    /// 设备注册客户端: 组装并发送 8 次上报时序的请求。
    /// 当前实现 Phase A: 01 报文 (POST /project/meta_info, meta_type=sub, scene=1)。
    ///
    /// 安全提示: 该客户端向拼多多生产服务器发送请求, 仅用于授权的逆向研究与
    /// 自有设备注册联调, 不得用于滥用、刷量或绕过风控的非法用途。
    /// </summary>
    public class RegisterClient
    {
        private const string ApiBase = "https://api.pinduoduo.com";
        private const string AppVersion = "8.8.0";
        private const string PddConfig = "V4:001.080800";
        private const string Xp1MetaInfoUl = "/project/meta_info"; // x-p1 入参 ul (爆破命中, 待真机坐实)

        /// <summary>
        /// 样本 01 的 key 字段 = RSA(固定random 0102..20) 用真机真实公钥加密。
        /// 复用它 + 固定 AES key 可绕过对 RSA 公钥 N 的依赖 (服务端私钥能正确解出 AES key)。
        /// </summary>
        private const string CapturedKeyField =
            "gbLMQDnhZW5TvwGU8k6Ts5b03sLarH0eGsTiBJQ4hZSvSdf1jnYY40zBc4Nru13UFDPyGQ0gex4BFwo56DHS8UFyzYxZpICTtHz1eHOfz29pxm/oqsBFLlDAheUjOT0ltBXaAtg/eDA9MzHRNPduRwKIUTOYlIn8SmpktwODpx4=";

        /// <summary>是否启用"固定 key 模式"(复用样本 RSA key 字段 + 固定 AES key), 用于绕过 RSA 公钥不确定。</summary>
        public bool UseCapturedKey { get; set; } = false;

        private readonly HttpClient _client;
        private readonly DeviceProfile _device;

        public RegisterClient(DeviceProfile device, string? proxyUrl = null)
        {
            _device = device;
            var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.All
            };
            if (!string.IsNullOrEmpty(proxyUrl))
            {
                handler.Proxy = new WebProxy(proxyUrl);
                handler.UseProxy = true;
                // 抓包代理常用自签证书, 联调时放行
                handler.ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
            }
            _client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(30),
                DefaultRequestVersion = new Version(2, 0),
                DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher
            };
        }

        /// <summary>
        /// 构造 01 报文的完整 HTTP 请求 (不发送, 用于检查/复现)。
        /// </summary>
        /// <param name="st">请求发起毫秒时间戳; null 则取当前</param>
        /// <param name="random32">body 加密随机; null 则真随机 (上线), 传固定值用于复现</param>
        /// <param name="pddid">已知 pddid; 带上则 body pddid 字段 + etag header 都填它 (验证设备识别)</param>
        public HttpRequestMessage Build01(long? st = null, byte[]? random32 = null, string pddid = "")
        {
            long stMs = st ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // mock 设备: 用请求时刻重算 user_env2 (它含 android_id + ts, 必须与本次请求一致)
            if (_device.IsMock)
                _device.RecomputeUserEnv2(stMs);

            // —— body —— (先生成 body, 它同时是 x-p1 的 bd 入参)
            string body = BuildBody01(random32, pddid);

            var req = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/project/meta_info?pdduid=")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            // content-type 带 charset
            req.Content.Headers.Remove("Content-Type");
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json;charset=UTF-8");

            // x-p1 的 bd = 本请求自身的 body JSON (已确认: sdr Map.bd = base64(body), 算法吃解码后原文)
            // et = pddid (注册首包空, 带 pddid 则用它)
            foreach (var (k, v) in BuildHeaders(stMs, bd: body, et: pddid))
                req.Headers.TryAddWithoutValidation(k, v);

            return req;
        }

        /// <summary>
        /// 生成 01 报文 body JSON。字段顺序与 Java 序列化一致 (含 '\/' 转义),
        /// 以保证它作为 x-p1 的 bd 入参时 seg1 计算正确。
        /// </summary>
        public string BuildBody01(byte[]? random32 = null, string pddid = "")
        {
            byte[] plaintext = MetaInfoSubBuilder.BuildPlaintext(_device, pddid: pddid);
            string packet = UseCapturedKey
                ? PddBodyCrypto.EncryptPacketWithCapturedKey(plaintext, CapturedKeyField)
                : PddBodyCrypto.EncryptPacket(plaintext, random32);
            string keyB64 = ExtractField(packet, "key");
            string dataB64 = ExtractField(packet, "data");
            long uptime = Environment.TickCount64 & 0x7FFFFFFF;
            // Java JSONObject 默认对 '/' 转义为 '\/'
            return "{\"key\":\"" + JsonEscapeSlash(keyB64) + "\"," +
                   "\"data\":\"" + JsonEscapeSlash(dataB64) + "\"," +
                   "\"platform\":\"android\",\"name\":\"pdd\"," +
                   "\"collect_begin_time\":" + uptime + ",\"collect_end_time\":" + (uptime + 174) + "}";
        }

        /// <summary>Java JSONObject 风格: 将 '/' 转义为 '\/'</summary>
        private static string JsonEscapeSlash(string s) => s.Replace("/", "\\/");

        /// <summary>发送任意已构造的请求 (复用本 client 的解压/超时配置)。用于对照实验。</summary>
        public async Task<RegisterResponse> SendRawAsync(HttpRequestMessage req)
        {
            var resp = await _client.SendAsync(req);
            string respBody = await resp.Content.ReadAsStringAsync();
            string? etag = resp.Headers.TryGetValues("etag", out var ev)
                ? string.Join(",", ev) : null;
            return new RegisterResponse
            {
                StatusCode = resp.StatusCode,
                Body = respBody,
                Etag = etag,
                Headers = resp.Headers
            };
        }

        /// <summary>发送 01 报文并返回响应。</summary>
        public async Task<RegisterResponse> Send01Async(long? st = null, byte[]? random32 = null, string pddid = "")
        {
            var req = Build01(st, random32, pddid);
            var resp = await _client.SendAsync(req);
            string respBody = await resp.Content.ReadAsStringAsync();
            string? etag = resp.Headers.TryGetValues("etag", out var ev)
                ? string.Join(",", ev) : null;
            return new RegisterResponse
            {
                StatusCode = resp.StatusCode,
                Body = respBody,
                Etag = etag,
                Headers = resp.Headers
            };
        }

        // ==================== 02 报文 (extra / data_type=1) ====================

        /// <summary>
        /// 构造 02 报文完整 HTTP 请求 (不发送)。02 不带 x-p1, 仅 anti-token。
        /// </summary>
        /// <param name="pddid">必填: 01 返回的 pdd_id (body pddid + header etag 同值)</param>
        /// <param name="st">anti-token 时间戳 ms; null 取当前</param>
        /// <param name="random32">body 加密随机; null 真随机, 传固定值用于复现</param>
        /// <param name="currentTimeMs">currentTime; null 取当前墙钟 ms</param>
        /// <param name="activeTimeMs">activeTime/upTime; null 取 uptime ms</param>
        /// <param name="processId">process_id; null 随机</param>
        /// <param name="collectBegin">collect_begin_time; null = activeTime-1</param>
        /// <param name="collectEnd">collect_end_time; null = activeTime + 随机</param>
        public HttpRequestMessage Build02(string pddid, long? st = null, byte[]? random32 = null,
            long? currentTimeMs = null, long? activeTimeMs = null, int? processId = null,
            long? collectBegin = null, long? collectEnd = null)
        {
            if (string.IsNullOrEmpty(pddid))
                throw new ArgumentException("02 报文必须带 01 下发的 pddid", nameof(pddid));

            long stMs = st ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            long curMs = currentTimeMs ?? stMs;
            // activeTime/upTime = 设备 uptime = 当前墙钟 - 开机时刻; 与 01 报文的 boot_time 自洽。
            long actMs = activeTimeMs ?? (curMs - _device.BootTime * 1000);
            int pid = processId ?? Random.Shared.Next(300, 30000);
            long cb = collectBegin ?? (actMs - 1);
            long ce = collectEnd ?? (actMs + Random.Shared.Next(400, 1200));

            string body = BuildBody02(pddid, random32, curMs, actMs, pid, cb, ce);

            var req = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/api/phantom/gbdbpdv/extra?pdduid=")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            req.Content.Headers.Remove("Content-Type");
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json;charset=UTF-8");

            foreach (var (k, v) in BuildHeaders02(stMs, pddid))
                req.Headers.TryAddWithoutValidation(k, v);

            return req;
        }

        /// <summary>生成 02 报文 body (encryptInfo 包装)。</summary>
        public string BuildBody02(string pddid, byte[]? random32,
            long currentTimeMs, long activeTimeMs, int processId, long collectBegin, long collectEnd)
        {
            byte[] plaintext = Extra02Builder.BuildPlaintext(_device, pddid, currentTimeMs, activeTimeMs, processId);
            string packet = UseCapturedKey
                ? PddBodyCrypto.EncryptPacketWithCapturedKey(plaintext, CapturedKeyField)
                : PddBodyCrypto.EncryptPacket(plaintext, random32);
            return Extra02Builder.WrapBody(packet, collectBegin, collectEnd);
        }

        /// <summary>发送 02 报文并返回响应。</summary>
        public async Task<RegisterResponse> Send02Async(string pddid, long? st = null, byte[]? random32 = null)
        {
            var req = Build02(pddid, st, random32);
            return await SendRawAsync(req);
        }

        /// <summary>02 报文 header 集 (照样本: 无 x-p1, 有 anti-token; etag=pddid)。</summary>
        private List<(string, string)> BuildHeaders02(long stMs, string pddid)
        {
            string antiToken = BuildAntiToken(stMs);
            string ua = BuildUserAgent();
            string queries =
                $"width={_device.ScreenWidth}&height={_device.ScreenHeight}&dpr={_device.Dpr}" +
                $"&net=1&brand={_device.Brand}&model={_device.Model}&osv={_device.Osv}&appv={AppVersion}&pl=2";

            var h = new List<(string, string)>
            {
                ("etag", pddid),
                ("referer", "Android"),
                ("p-appname", "pinduoduo"),
                ("p-proc-time", Random.Shared.Next(1000, 5000).ToString()),
                ("x-pdd-info", "bold_free%3Dfalse%26bold_product%3D%26front%3D1%26tz%3DAsia%2FShanghai"),
                ("x-pdd-queries", queries),
                ("accept-language", "zh-CN"),
                ("x-app-lang", "zh"),
                ("x-app-ui", "dm%3D0%26zm%3D0"),
                ("x-client-language", "zh"),
                ("x-client-region", "1"),
                ("p-proc", "main"),
                ("p-mediainfo", "player=1.0.3&rtc=1.0.0"),
                ("x-b3-ptracer", "hctrue" + RandomHex(26)),
                ("user-agent", ua),
                ("pdd-config", PddConfig),
                ("multi-set", "0,1,"),
                ("accept-encoding", "gzip"),
                ("anti-token", antiToken),
            };
            if (!string.IsNullOrEmpty(_device.HeaderApiUid))
                h.Add(("cookie", $"api_uid={_device.HeaderApiUid}"));
            return h;
        }

        // ==================== 03 报文 (extra / data_type=20, 双层) ====================

        /// <summary>
        /// 生成 03 内层 s_f_d 包 {key,data}。
        /// ⚠ 内层应使用 libdyncommon RSA 公钥, 当前未提取 → 暂用 PddBodyCrypto (libpdd_secure 公钥) 占位。
        /// 仅用于离线 JSON 对比/自测; 真随机 key 上线需替换为 libdyncommon 公钥。
        /// </summary>
        public string BuildInner03Package(byte[]? random32 = null, string? randB64 = null)
        {
            byte[] inner = Extra03Builder.BuildInnerPlaintext(_device, randB64);
            return UseCapturedKey
                ? PddBodyCrypto.EncryptPacketWithCapturedKey(inner, CapturedKeyField)
                : PddBodyCrypto.EncryptPacket(inner, random32);
        }

        /// <summary>生成 03 完整 body (双层 encryptInfo 包装)。</summary>
        public string BuildBody03(string pddid, byte[]? random32 = null, string? randB64 = null,
            long? collectBegin = null, long? collectEnd = null)
        {
            string innerPkg = BuildInner03Package(random32, randB64);
            byte[] outer = Extra03Builder.BuildOuterPlaintext(pddid, innerPkg);
            string outerPkg = UseCapturedKey
                ? PddBodyCrypto.EncryptPacketWithCapturedKey(outer, CapturedKeyField)
                : PddBodyCrypto.EncryptPacket(outer, random32);
            long uptime = Environment.TickCount64 & 0x7FFFFFFF;
            long cb = collectBegin ?? (uptime - 1);
            long ce = collectEnd ?? (uptime + Random.Shared.Next(400, 1200));
            return Extra02Builder.WrapBody(outerPkg, cb, ce);
        }

        /// <summary>构造 03 报文请求 (不发送)。header 同 02 (无 x-p1, 有 anti-token, etag=pddid)。</summary>
        public HttpRequestMessage Build03(string pddid, long? st = null, byte[]? random32 = null)
        {
            if (string.IsNullOrEmpty(pddid))
                throw new ArgumentException("03 报文必须带 01 下发的 pddid", nameof(pddid));
            long stMs = st ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string body = BuildBody03(pddid, random32);
            var req = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/api/phantom/gbdbpdv/extra?pdduid=")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            req.Content.Headers.Remove("Content-Type");
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json;charset=UTF-8");
            foreach (var (k, v) in BuildHeaders02(stMs, pddid))
                req.Headers.TryAddWithoutValidation(k, v);
            return req;
        }

        /// <summary>发送 03 报文并返回响应。</summary>
        public async Task<RegisterResponse> Send03Async(string pddid, long? st = null, byte[]? random32 = null)
        {
            return await SendRawAsync(Build03(pddid, st, random32));
        }

        // ==================== 05 报文 (extra / data_type=17, wtp) ====================

        /// <summary>
        /// 生成 05 报文 body (单层 encryptInfo, 无 collect_*time)。
        /// </summary>
        /// <param name="pddid">必填: 01 下发的 pdd_id (同 header etag)</param>
        /// <param name="random32">body 加密随机; null 真随机, 传固定值用于复现</param>
        /// <param name="wtp">wtp 字段值; null 则按 WtpCodec.DefaultIp 现算成功形态
        /// (上线应改为按 mock 出口实际解析 strc.pinduoduo.com 的 IP)</param>
        public string BuildBody05(string pddid, byte[]? random32 = null, string? wtp = null)
        {
            string wtpVal = wtp ?? WtpCodec.Encode(WtpCodec.DefaultIp);
            byte[] plaintext = Extra05Builder.BuildPlaintext(pddid, wtpVal);
            string packet = UseCapturedKey
                ? PddBodyCrypto.EncryptPacketWithCapturedKey(plaintext, CapturedKeyField)
                : PddBodyCrypto.EncryptPacket(plaintext, random32);
            return Extra05Builder.WrapBody(packet);
        }

        /// <summary>构造 05 报文请求 (不发送)。header 同 02 (无 x-p1, 有 anti-token, etag=pddid)。</summary>
        public HttpRequestMessage Build05(string pddid, long? st = null, byte[]? random32 = null, string? wtp = null)
        {
            if (string.IsNullOrEmpty(pddid))
                throw new ArgumentException("05 报文必须带 01 下发的 pddid", nameof(pddid));
            long stMs = st ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string body = BuildBody05(pddid, random32, wtp);
            var req = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/api/phantom/gbdbpdv/extra?pdduid=")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            req.Content.Headers.Remove("Content-Type");
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json;charset=UTF-8");
            foreach (var (k, v) in BuildHeaders02(stMs, pddid))
                req.Headers.TryAddWithoutValidation(k, v);
            return req;
        }

        /// <summary>发送 05 报文并返回响应。</summary>
        public async Task<RegisterResponse> Send05Async(string pddid, long? st = null, byte[]? random32 = null, string? wtp = null)
        {
            return await SendRawAsync(Build05(pddid, st, random32, wtp));
        }

        // ==================== headers ====================

        private List<(string, string)> BuildHeaders(long stMs, string bd, string et = "")
        {
            string xp1 = XP1Codec.Generate(
                ul: Xp1MetaInfoUl,
                bdJson: bd,
                et: et,                 // 注册首包空; 带已知 pddid 时用它
                st: stMs.ToString(),
                p47: _device.P47,
                ac: "", ck: "");

            string antiToken = BuildAntiToken(stMs);
            string ua = BuildUserAgent();
            string queries =
                $"width={_device.ScreenWidth}&height={_device.ScreenHeight}&dpr={_device.Dpr}" +
                $"&net=1&brand={_device.Brand}&model={_device.Model}&osv={_device.Osv}&appv={AppVersion}&pl=2";

            var h = new List<(string, string)>
            {
                ("etag", et),                              // 注册首包空; 带已知 pddid 则回填
                ("referer", "Android"),
                ("x-p1", xp1),
                ("accept-language", "zh-CN"),
                ("p-proc-time", Random.Shared.Next(1000, 5000).ToString()),
                ("x-pdd-queries", queries),
                ("p-appname", "pinduoduo"),
                ("multi-set", "0,0,"),
                ("x-p-t", "t=0&x-p1-t=0"),
                ("pdd-config", PddConfig),
                ("x-pdd-info", "bold_free%3Dfalse%26bold_product%3D%26front%3D1%26tz%3DAsia%2FShanghai"),
                ("x-b3-ptracer", "hctrue" + RandomHex(30)),
                ("x-app-ui", "dm%3D0%26zm%3D0"),
                ("accept-encoding", "gzip"),
                ("p-proc", "main"),
                ("user-agent", ua),
                ("anti-token", antiToken),
            };
            if (!string.IsNullOrEmpty(_device.HeaderApiUid))
                h.Insert(3, ("cookie", $"api_uid={_device.HeaderApiUid}"));
            return h;
        }

        /// <summary>anti-token = info4(): "2ag" + base64(AES(plaintext)), 无 serverId 版 (type 0x0F)</summary>
        private string BuildAntiToken(long stMs)
        {
            byte[] pt = Info4Codec.BuildPlaintext(
                androidIdHex: _device.AndroidId,
                timestampMs: stMs,
                serverId: "",
                uuid: ParseUuidOrRandom(_device.Uuid));
            return Info4Codec.Encrypt(pt);
        }

        private string BuildUserAgent() =>
            $"android Mozilla/5.0 (Linux; Android {_device.Osv}; {_device.Model} Build/{_device.BuildId}; wv) " +
            "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/143.0.7499.192 Safari/537.36 " +
            $" phh_android_version/{AppVersion} phh_android_build/24f4a9fb4f113b97ad7e6958d27ee140996d17a7" +
            " phh_android_channel/main_guanwang pversion/0";

        // ==================== helpers ====================

        private static Guid ParseUuidOrRandom(string s)
            => Guid.TryParse(s, out var g) ? g : Guid.NewGuid();

        private static string RandomHex(int n)
        {
            const string h = "0123456789abcdef";
            var sb = new StringBuilder(n);
            for (int i = 0; i < n; i++) sb.Append(h[Random.Shared.Next(16)]);
            return sb.ToString();
        }

        /// <summary>从 {"key":"X","data":"Y"} 取出某字段的原始值 (不含引号)。
        /// 注意: PddBodyCrypto 输出的 base64 不含 '"', 直接定位到下一个 '"' 即可。</summary>
        private static string ExtractField(string packet, string field)
        {
            string marker = $"\"{field}\":\"";
            int s = packet.IndexOf(marker, StringComparison.Ordinal) + marker.Length;
            int e = packet.IndexOf('"', s);
            return packet[s..e];
        }
    }

    public class RegisterResponse
    {
        public HttpStatusCode StatusCode { get; set; }
        public string Body { get; set; } = "";
        public string? Etag { get; set; }
        public System.Net.Http.Headers.HttpResponseHeaders? Headers { get; set; }
    }
}
