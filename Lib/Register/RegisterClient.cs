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

        public RegisterClient(DeviceProfile device, string? proxyUrl = null, CookieContainer? cookieContainer = null)
        {
            _device = device;
            var handler = new HttpClientHandler
            {
                AutomaticDecompression = DecompressionMethods.All
            };
            if (cookieContainer != null)
            {
                handler.CookieContainer = cookieContainer;   // 与业务/登录共用, 自动收发 api_uid
                handler.UseCookies = true;
            }
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
            return WrapMetaInfoBody(plaintext, random32);
        }

        /// <summary>
        /// 把 meta_info 表单 plaintext 封成 01/04 通用的 body JSON:
        /// {"key","data","platform","name","collect_begin_time","collect_end_time"}。
        /// '/' 按 Java JSONObject 习惯转义为 '\/' (保证作 x-p1 bd 入参时 seg 计算正确)。
        /// </summary>
        private string WrapMetaInfoBody(byte[] plaintext, byte[]? random32)
        {
            string packet = UseCapturedKey
                ? PddBodyCrypto.EncryptPacketWithCapturedKey(plaintext, CapturedKeyField)
                : PddBodyCrypto.EncryptPacket(plaintext, random32);
            string keyB64 = ExtractField(packet, "key");
            string dataB64 = ExtractField(packet, "data");
            long uptime = Environment.TickCount64 & 0x7FFFFFFF;
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

            Log.Debug($"设备注册 SendRawAsync-> {respBody}");

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

            Log.Debug($"设备注册Send01Async -> {respBody}");

            return new RegisterResponse
            {
                StatusCode = resp.StatusCode,
                Body = respBody,
                Etag = etag,
                Headers = resp.Headers
            };
        }

        // ==================== 04 报文 (meta_info / meta_type=all / scene=1) ====================

        /// <summary>
        /// 构造 04 报文完整 HTTP 请求 (不发送)。
        /// 04 = 01 同接口/同单层加密/同 header 集, 仅 meta_type=all 全量填充字段。
        /// </summary>
        /// <param name="pddid">01 下发的 pdd_id (body pddid + header etag 同值)。空则按全新设备 known_device=0。</param>
        /// <param name="st">请求发起 ms; null 取当前</param>
        /// <param name="random32">body 加密随机; null 真随机, 传固定值用于复现</param>
        /// <param name="options">04 会话/运行时参数; null 则按 mock 设备现状自动生成</param>
        public HttpRequestMessage Build04(string pddid, long? st = null, byte[]? random32 = null,
            Meta04Options? options = null)
        {
            long stMs = st ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // 04 用 an/pk/extra 长... 实为 Report04 形态 (含 android_id, 必须与本次请求 ts 自洽)
            if (_device.IsMock)
                _device.RecomputeUserEnv2(stMs, form: DeviceProfile.UserEnv2Form.Report04);

            Meta04Options opt = options ?? BuildMock04Options(pddid, stMs);
            string body = BuildBody04(opt, random32);

            var req = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/project/meta_info?pdduid=")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            req.Content.Headers.Remove("Content-Type");
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json;charset=UTF-8");

            // 04 header 集与 01 相同 (x-p1 ul=/project/meta_info, bd=本 body, et=pddid)
            foreach (var (k, v) in BuildHeaders(stMs, bd: body, et: pddid))
                req.Headers.TryAddWithoutValidation(k, v);

            return req;
        }

        /// <summary>生成 04 报文 body JSON (单层加密, 与 01 同封装)。</summary>
        public string BuildBody04(Meta04Options opt, byte[]? random32 = null)
        {
            byte[] plaintext = MetaInfoAllBuilder.BuildPlaintext(_device, opt);
            return WrapMetaInfoBody(plaintext, random32);
        }

        /// <summary>
        /// 按当前 (mock) 设备现状生成 04 的会话/运行时参数:
        /// known_device 随是否持有 pddid, p85/fk_data 联动本次会话 dynso 时间戳, mediaDrm 按设备 Widevine ID 重建。
        /// </summary>
        public Meta04Options BuildMock04Options(string pddid, long stMs)
        {
            long dynsoTs = stMs - Random.Shared.Next(2000, 12000);
            string dynsoRand = Random.Shared.NextInt64(0, 10_000_000_000L).ToString("D10");
            string p85Hex = DeviceMocker.RandomHex(5);
            string p85Plain = PFieldsCodec.BuildP85Plain(dynsoTs, p85Hex);

            return new Meta04Options
            {
                Pddid = pddid,
                KnownDevice = string.IsNullOrEmpty(pddid) ? 0 : 1,  // 已持有 pddid → 已知设备
                Cookie = _device.BodyCookie,                        // mock 新设备已置空
                CurrentTimeMs = stMs,
                InstallTimeMs = _device.P46InstallTime,
                AppUpdateTimeMs = _device.P46InstallTime,
                BootTime = _device.BootTime,
                LocalSequence = 1,
                P26 = MetaInfoAllBaseline.P26Mock,                  // 干净设备无用户 CA
                DynsoLoadTs = dynsoTs,
                P85 = PFieldsCodec.EncodeWire("p85", p85Plain),     // 与 fk_data.dynso_load_ts 联动
                MediaDrm = MetaInfoAllBuilder.BuildMediaDrmWire(_device.MediaDrmWidevineId),
                FkData = FkDataBuilder.Build(dynsoTs, dynsoRand),
            };
        }

        /// <summary>发送 04 报文并返回响应。</summary>
        public async Task<RegisterResponse> Send04Async(string pddid, long? st = null,
            byte[]? random32 = null, Meta04Options? options = null)
        {
            return await SendRawAsync(Build04(pddid, st, random32, options));
        }

        /// <summary>
        /// 登录后账号↔设备绑定上报 (meta_type=all, scene=4, 带 uid)。
        /// 真机在登录成功后会再发一次 /project/meta_info?pdduid={uid}, 明文含 uid + pddid,
        /// 把账号绑定到设备。缺这一步 → 服务端视为"账号+未绑定设备"→ 业务接口(如 render)降级(售罄)。
        /// 见 examples/compare/render/meta_after_signin_decrypted.txt。
        /// </summary>
        public HttpRequestMessage BuildSigninMeta(string pddid, long uid, string accessToken,
            long? st = null, byte[]? random32 = null)
        {
            long stMs = st ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            if (_device.IsMock)
                _device.RecomputeUserEnv2(stMs, form: DeviceProfile.UserEnv2Form.Report04);

            Meta04Options opt = BuildMock04Options(pddid, stMs);
            opt.Scene = 4;                     // 登录场景
            opt.KnownDevice = 1;               // 已注册设备
            opt.Uid = uid.ToString();          // ★ 绑定账号 uid

            string body = BuildBody04(opt, random32);

            // pdduid 用登录 uid (注册期的 04 是空 pdduid)
            var req = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/project/meta_info?pdduid={uid}")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            req.Content.Headers.Remove("Content-Type");
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json;charset=UTF-8");

            // 头集同 04 (x-p1 ul=/project/meta_info, et=pddid); 追加登录态 accesstoken, x-p-t 切登录形态
            foreach (var (k, v) in BuildHeaders(stMs, bd: body, et: pddid))
            {
                if (k == "x-p-t") continue;    // 用登录形态覆盖
                req.Headers.TryAddWithoutValidation(k, v);
            }
            req.Headers.TryAddWithoutValidation("x-p-t", "t=1&x-p1-t=0");
            if (!string.IsNullOrEmpty(accessToken))
                req.Headers.TryAddWithoutValidation("accesstoken", accessToken);

            return req;
        }

        /// <summary>发送登录后账号↔设备绑定上报。</summary>
        public async Task<RegisterResponse> SendSigninMetaAsync(string pddid, long uid, string accessToken,
            long? st = null, byte[]? random32 = null)
        {
            return await SendRawAsync(BuildSigninMeta(pddid, uid, accessToken, st, random32));
        }

        // ==================== 06 报文 (meta_info / meta_type=all / scene=14) ====================

        /// <summary>06 user_env2 内嵌 extra 字段 ("01"+base64); null=复刻样本基线。
        /// mock 全新干净设备如需重算 (adb 关闭等), 可传 EncryptMock(真实 G) 产出的字段。</summary>
        public string? Extra06Field { get; set; } = null;

        /// <summary>
        /// 构造 06 报文完整 HTTP 请求 (不发送)。
        /// 06 = 04 同接口/同加密/同 header, 差异: scene=14, 多 p48 字段, user_env2 切 Form06 长形态。
        /// </summary>
        /// <param name="pddid">已注册设备的 pdd_id (body pddid + header etag)</param>
        /// <param name="st">请求发起 ms; null 取当前</param>
        /// <param name="random32">body 加密随机; null 真随机</param>
        /// <param name="options">06 会话/运行时参数; null 按 mock 现状生成 (scene=14 + p48 + Form06 user_env2)</param>
        public HttpRequestMessage Build06(string pddid, long? st = null, byte[]? random32 = null,
            Meta04Options? options = null)
        {
            long stMs = st ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            Meta04Options opt = options ?? BuildMock06Options(pddid, stMs);
            string body = BuildBody04(opt, random32);   // 06 body 封装与 04 完全一致

            var req = new HttpRequestMessage(HttpMethod.Post, $"{ApiBase}/project/meta_info?pdduid=")
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            };
            req.Content.Headers.Remove("Content-Type");
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/json;charset=UTF-8");

            foreach (var (k, v) in BuildHeaders(stMs, bd: body, et: pddid))
                req.Headers.TryAddWithoutValidation(k, v);

            return req;
        }

        /// <summary>
        /// 按当前 (mock) 设备现状生成 06 会话/运行时参数:
        /// 在 04 基础上置 scene=14、生成 p48、把 user_env2 切成 Form06 长形态
        /// (含 realtime 分辨率 + 内嵌 extra 检测容器)。
        /// </summary>
        public Meta04Options BuildMock06Options(string pddid, long stMs)
        {
            var opt = BuildMock04Options(pddid, stMs);
            opt.Scene = 14;
            // p48: 充电状态行, ts 取略早于请求时刻 (复刻样本形态)
            opt.P48 = $"CHG|{stMs - Random.Shared.Next(1000, 4000)}|0|false|内置屏幕|null|1";

            // user_env2 长形态 (Form06): id=本机 android_id, ts=请求时刻, extra=基线/自定义
            string extraField = Extra06Field ?? Ue2Form06Baseline.ExtraField;
            int ue2Seq = Random.Shared.Next(8, 40);   // ues 内部独立 seq (样本 11); 服务端不强校验具体值
            var plain = UserEnv2Codec.Form06(
                _device.AndroidId, stMs, ue2Seq, Ue2Form06Baseline.RealtimeContent, extraField);
            opt.UserEnv2 = UserEnv2Codec.GenerateFrom(plain);
            return opt;
        }

        /// <summary>发送 06 报文并返回响应。</summary>
        public async Task<RegisterResponse> Send06Async(string pddid, long? st = null,
            byte[]? random32 = null, Meta04Options? options = null)
        {
            return await SendRawAsync(Build06(pddid, st, random32, options));
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

        // ==================== 07 / 08 报文 (extra / data_type=15 / 21) ====================

        /// <summary>构造 07/08 报文请求 (extra, 单层 encryptInfo, 无 collect_time; header 同 02)。</summary>
        private HttpRequestMessage BuildExtraSimple(string pddid, byte[] plaintext, long? st)
        {
            long stMs = st ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string packet = UseCapturedKey
                ? PddBodyCrypto.EncryptPacketWithCapturedKey(plaintext, CapturedKeyField)
                : PddBodyCrypto.EncryptPacket(plaintext, null);
            string body = Extra05Builder.WrapBody(packet);   // 仅 encryptInfo, 无 collect_time
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

        /// <summary>
        /// 07 报文 (data_type=15, es)。es=null 时用 <see cref="Type15Builder"/> **动态生成**
        /// (p61=本次ts, p97=设备安装时间, p75=设备 base.apk 路径, p84/p93="{ts}_1"; 其余干净基线);
        /// 传入 es 则原样用 (复刻/调试)。dv 控制版本 (19 含 p131 / 18 无), 内外一致。
        /// </summary>
        public HttpRequestMessage Build07(string pddid, long? st = null, string? es = null, int dv = 19)
        {
            if (string.IsNullOrEmpty(pddid)) throw new ArgumentException("07 需要 pddid", nameof(pddid));
            long stMs = st ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string esVal = es ?? Type15Builder.BuildEs(BuildType15Options(stMs, dv));
            return BuildExtraSimple(pddid, Extra0708Builder.BuildPlaintext07(pddid, esVal, dv), stMs);
        }

        /// <summary>由设备 + 请求时刻组装 type15 es 明文参数 (mock 动态字段)。</summary>
        private Type15Options BuildType15Options(long stMs, int dv) => new Type15Options
        {
            Dv = dv,
            ReportTs = stMs,                    // p61
            InstallTs = _device.P46InstallTime, // p97
            P75Plain = _device.ApkPath,         // p75 base.apk 路径
            P84Plain = stMs + "_1",             // "{ts}_1" (15B, 贴合 p84 keystream)
            P93Plain = stMs + "_1",
            // p62/p70/p71/p74/p98 = so版本固定/指纹类, 用 Type15Baseline 干净基线
        };

        /// <summary>08 报文 (data_type=21, info)。info=null 时用 <see cref="Info08Builder"/>
        /// **动态生成** (Type21Codec 编码 attestation 证书链, 默认基线证书); 传入 info 则原样用 (复刻/调试)。</summary>
        public HttpRequestMessage Build08(string pddid, long? st = null, string? info = null)
        {
            if (string.IsNullOrEmpty(pddid)) throw new ArgumentException("08 需要 pddid", nameof(pddid));
            return BuildExtraSimple(pddid, Extra0708Builder.BuildPlaintext08(pddid, info), st);
        }

        /// <summary>发送 07 报文 (es 动态生成; dv 默认 19)。</summary>
        public async Task<RegisterResponse> Send07Async(string pddid, long? st = null, string? es = null, int dv = 19)
            => await SendRawAsync(Build07(pddid, st, es, dv));

        /// <summary>发送 08 报文。</summary>
        public async Task<RegisterResponse> Send08Async(string pddid, long? st = null, string? info = null)
            => await SendRawAsync(Build08(pddid, st, info));

        // ==================== 16 报文 (extra / data_type=16, proc-maps 注入检测) ====================

        /// <summary>
        /// 16 报文 (data_type=16, code/r)。r = base64(XOR_0x4A(maps 路径清单)), 见 <see cref="Type16Builder"/>。
        /// 新流程独有 (旧 01~08 序列无此项), 检测 /proc/self/maps 里的注入 so。
        /// 外层信封与 02/03/05/07/08 同 (单层 encryptInfo)。mapsRegions=null 用干净基线。
        /// </summary>
        public HttpRequestMessage Build16(string pddid, long? st = null, string? mapsRegions = null)
        {
            if (string.IsNullOrEmpty(pddid)) throw new ArgumentException("16 需要 pddid", nameof(pddid));
            long stMs = st ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            // maps 清单里的 app 安装 ~~段 与 type15.p75 联动: 用设备的随机段替换基线段, 保证两报文一致。
            string maps = mapsRegions ?? Type16Baseline.MapsRegions
                .Replace(DeviceProfile.BaselineApkSeg1, _device.ApkDirSeg1)
                .Replace(DeviceProfile.BaselineApkSeg2, _device.ApkDirSeg2);
            return BuildExtraSimple(pddid, Type16Builder.BuildPlaintext(pddid, maps), stMs);
        }

        /// <summary>发送 16 报文。</summary>
        public async Task<RegisterResponse> Send16Async(string pddid, long? st = null, string? mapsRegions = null)
            => await SendRawAsync(Build16(pddid, st, mapsRegions));

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
