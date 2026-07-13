using System.Text.RegularExpressions;
using Newtonsoft.Json.Linq;
using PddLib.Crypto;
using PddLib.Models;
using PddLib.Register;

namespace PddLib
{
    /// <summary>
    /// anti-token 类型 (info4/info2 互斥, 按接口选择)。
    ///   None  = 不带 anti-token
    ///   Info4 = "2ag" (DeviceNative.info4, 30B 定长)  → 注册/业务接口 (如 integration/render)
    ///   Info2 = "2af" (info2, 设备信息大 TLV+GZIP)    → 登录类接口 (mobile/code/request, login_mobile)
    /// </summary>
    public enum AntiTokenKind { None, Info4, Info2 }

    /// <summary>发码成功后, 供 Login 获取短信验证码的上下文。</summary>
    public class SmsCodeRequestContext
    {
        public string Mobile = "";
        public string TelCode = "86";
        public string CountryId = "1";
        /// <summary>发送验证码接口的响应 (可含下发的 code_id / 提示等)。</summary>
        public HttpResult SendCodeResponse = null!;
    }

    /// <summary>验证码提供委托: 登录发码成功后被调用, 返回收到的验证码 (可异步等待用户/短信服务)。</summary>
    public delegate Task<string> SmsCodeHandler(SmsCodeRequestContext ctx);

    /// <summary>登录结果。</summary>
    public class LoginResult
    {
        public bool Success;
        public string Stage = "";      // send_code / await_code / login
        public string Message = "";
        public HttpResult? SendCodeResponse;
        public HttpResult? LoginResponse;
        public Session? Session;
    }

    /// <summary>
    /// Android 主类: 承载一台已注册的 mock 设备 (DeviceProfile) 及其注册结果 (pddid),
    /// 供后续业务接口调用复用同一套设备指纹/会话。
    ///
    /// 典型用法:
    ///   var android = await Android.CreateNewAsync(devApiBase, devApiKey, devApiSecret);
    ///   // android.Device (机型指纹) / android.Pddid (注册下发) 已就绪
    ///
    /// 安全: 仅用于授权的逆向研究与自有设备注册联调。
    /// </summary>
    public class Android
    {
        /// <summary>mock 设备指纹 (由淘宝真机转换 + 唯一值随机化而来)。</summary>
        public DeviceProfile Device { get; }

        /// <summary>登录会话 (注册阶段为空; 登录后填充)。</summary>
        public Session Session { get; set; }

        /// <summary>注册流程封装 (01~08)。</summary>
        public RegisterClient Register { get; }

        public Http Http { get; }

        /// <summary>服务端下发的 pdd_id (01 返回)。</summary>
        public string Pddid { get; private set; } = string.Empty;

        private const string ApiBase = "https://api.pinduoduo.com";
        private const string AppVersion = "8.8.0";
        private const string AppBuildHash = "24f4a9fb4f113b97ad7e6958d27ee140996d17a7";
        private string verifyAuthToken = string.Empty;

        private readonly string? _proxyUrl;

        /// <summary>
        /// 验证码提供委托: 实例化后自行注册 (或构造时传入)。
        /// Login 发码成功后调用它获取验证码, 满足不同场景 (人工输入/接码平台/短信监听等)。
        /// </summary>
        public SmsCodeHandler? SmsCodeProvider { get; set; }

        /// <summary>注册与业务/登录共用的 cookie 容器 (自动管理 api_uid 等)。</summary>
        public System.Net.CookieContainer Cookies { get; }

        public Android(DeviceProfile device, string? proxyUrl = null,
            string? proxyUsername = null, string? proxyPassword = null,
            SmsCodeHandler? smsCodeProvider = null)
        {
            Device = device;
            Session = new Session();
            // 注册与业务/登录共用一个 CookieContainer → 01 的 Set-Cookie(api_uid) 自动落入,
            // 后续 02~08 / 登录 / 业务请求自动带上, 无需手动 cookie 头。
            Cookies = new System.Net.CookieContainer();
            Register = new RegisterClient(device, proxyUrl, Cookies);
            Http = new Http(proxyUrl, proxyUsername, proxyPassword, Cookies);
            _proxyUrl = proxyUrl;
            SmsCodeProvider = smsCodeProvider;
        }

        /// <summary>
        /// 创建并注册一台全新设备:
        ///   1) 从设备库网关随机取一台淘宝真机记录 (RepedCrypto 解码检测项);
        ///   2) 转换器出机型基准 + mocker 随机化唯一值 → DeviceProfile;
        ///   3) 走 01~08 注册时序, 保存 pddid 与相关字段到实例。
        /// </summary>
        public static async Task<Android> CreateNewAsync(
            string? proxyUrl = null, string? proxyUsername = null, string? proxyPassword = null,
            SmsCodeHandler? smsCodeProvider = null)
        {
            // 1) 取淘宝真机 (设备库网关凭据内置于 ClientApi) → 2) 转 mock 设备 (保留机型, 随机唯一值)
            var api = ClientApi.Default();
            var tao = await api.GetRandomTaobaoDeviceAsync();
            var device = DeviceMocker.NewDeviceFromTaobao(tao, out _);

            var android = new Android(device, proxyUrl, proxyUsername, proxyPassword, smsCodeProvider);
            if (!await android.RegisterDevice())
                throw new Exception("注册设备失败: 01 未取得 pdd_id");
            return android;
        }

        /// <summary>
        /// 走完整 01~08 注册时序: 01 拿 pddid (并回填 api_uid cookie), 其余用该 pddid 上报。
        /// 返回是否成功取得 pddid (02~08 失败仅记录, 不影响注册成立)。
        /// </summary>
        public async Task<bool> RegisterDevice()
        {
            long stMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // 01: meta_info(sub, scene=1) → pdd_id
            var r01 = await Register.Send01Async(stMs);
            Pddid = ExtractPddId(r01.Body);
            //CaptureApiUid(r01);
            if (string.IsNullOrEmpty(Pddid))
                return false;

            // 02~08 + 16: 复用 pddid (失败不阻断, 注册已成立)
            await TrySend(() => Register.Send02Async(Pddid));
            await TrySend(() => Register.Send03Async(Pddid));
            await TrySend(() => Register.Send16Async(Pddid));  // data_type=16 proc-maps 注入检测 (新流程独有; 紧邻 s_f_d 检测组)
            await TrySend(() => Register.Send04Async(Pddid));
            await TrySend(() => Register.Send05Async(Pddid));
            await TrySend(() => Register.Send06Async(Pddid));
            await TrySend(() => Register.Send07Async(Pddid));  // data_type=15 es (Type15Builder 动态生成)
            await TrySend(() => Register.Send08Async(Pddid));

            return true;
        }

        private static async Task TrySend(Func<Task<RegisterResponse>> send)
        {
            try { await send(); } catch { /* 子模块上报失败不阻断注册 */ }
        }

        /// <summary>从响应体解析 pdd_id。</summary>
        private static string ExtractPddId(string body)
        {
            var m = Regex.Match(body ?? "", "\"pdd_id\":\"([^\"]+)\"");
            return m.Success ? m.Groups[1].Value : "";
        }

        /// <summary>从响应 Set-Cookie 抓 api_uid, 回填到设备 (后续请求 cookie 头复用)。</summary>
        private void CaptureApiUid(RegisterResponse resp)
        {
            if (resp.Headers != null && resp.Headers.TryGetValues("set-cookie", out var cookies))
            {
                foreach (var c in cookies)
                {
                    var m = Regex.Match(c, "api_uid=([^;]+)");
                    if (m.Success) { Device.HeaderApiUid = m.Groups[1].Value; break; }
                }
            }
        }

        // ==================== 业务接口 (注册后复用同一设备/pddid) ====================

        /// <summary>
        /// 构建业务公共请求头 (基于已注册的 DeviceProfile + pddid)。
        /// </summary>
        /// <param name="extra">追加/覆盖的自定义头</param>
        /// <param name="antiToken">anti-token 类型 (None/Info4/Info2, 互斥)</param>
        /// <param name="xp1Path">非空则生成 x-p1 (对 body 的自签名), ul 取该请求路径</param>
        /// <param name="xp1Body">x-p1 的 bd 入参 = 本请求实际发送的 body JSON 原文</param>
        private Dictionary<string, string> BuildHeaders(Dictionary<string, string>? extra = null,
            AntiTokenKind antiToken = AntiTokenKind.None,
            string? xp1Path = null, string? xp1Body = null)
        {
            string ua =
                $"android Mozilla/5.0 (Linux; Android {Device.Osv}; {Device.Model} Build/{Device.BuildId}; wv) " +
                "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/143.0.7499.192 Safari/537.36 " +
                $" phh_android_version/{AppVersion} phh_android_build/{AppBuildHash}" +
                " phh_android_channel/main_guanwang pversion/0";

            string queries =
                $"width={Device.ScreenWidth}&height={Device.ScreenHeight}&net=1&brand={Device.Brand}" +
                $"&model={Device.Model}&osv={Device.Osv}&appv={AppVersion}&pl=2";

            var headers = new Dictionary<string, string>
            {
                ["etag"] = Pddid,
                ["referer"] = "Android",
                ["content-type"] = "application/json;charset=UTF-8",
                ["user-agent"] = ua,
                ["accept-encoding"] = "gzip",
                ["accept-language"] = "zh-Hans-CN",
                ["p-appname"] = "pinduoduo",
                ["p-mediainfo"] = "player=1.0.3&rtc=1.0.0",
                ["p-proc"] = "main",
                ["x-app-lang"] = "zh",
                ["x-pdd-queries"] = queries,
                ["pdd-config"] = "V4:001.080800",
                ["x-app-ui"] = "dm%3D0%26zm%3D0",
                ["x-pdd-info"] = "bold_free%3Dfalse%26bold_product%3D%26front%3D1%26tz%3DAsia%2FShanghai",
                ["x-b3-ptracer"] = "hctrue" + DeviceMocker.RandomHex(15),
            };
            if (!string.IsNullOrEmpty(Session.AccessToken))
                headers["accesstoken"] = Session.AccessToken;

            if (!string.IsNullOrEmpty(verifyAuthToken))
            {
                headers["verifyauthtoken"] = verifyAuthToken;
            }

            //if (!string.IsNullOrEmpty(Device.HeaderApiUid))
            //    headers["cookie"] = $"api_uid={Device.HeaderApiUid}";

            long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // anti-token: info4(2ag) 与 info2(2af) 互斥
            if (antiToken == AntiTokenKind.Info4)
            {
                byte[] pt = Info4Codec.BuildPlaintext(
                    androidIdHex: Device.AndroidId,
                    timestampMs: nowMs,
                    serverId: "",
                    uuid: Guid.TryParse(Device.Uuid, out var g) ? g : Guid.NewGuid());
                headers["anti-token"] = Info4Codec.Encrypt(pt);
            }
            else if (antiToken == AntiTokenKind.Info2)
            {
                headers["anti-token"] = Info2Builder.BuildAntiToken(Device, nowMs);
            }

            // x-p1: 对请求 body 的自签名 (登录等敏感接口)。ul=请求路径, bd=本请求 body 原文,
            // et=pddid, st=时间戳, p47=会话 UUID。算法见 06_xp1_algorithm.md。
            if (!string.IsNullOrEmpty(xp1Path) && xp1Body != null)
            {
                headers["x-p1"] = XP1Codec.Generate(
                    ul: xp1Path,
                    bdJson: xp1Body,
                    et: Pddid,
                    st: nowMs.ToString(),
                    p47: Device.P47,
                    ac: "", ck: "");
            }

            if (extra != null)
                foreach (var kv in extra) headers[kv.Key] = kv.Value;

            return headers;
        }

        /// <summary>获取商品详情 (integration/render), 返回完整 HTTP 结果。</summary>
        public async Task<HttpResult> GetItemDetailFullAsync(string goodsId)
        {
            var url = $"{ApiBase}/api/oak/integration/render?pdduid={Session.Uid}";
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var body = new Dictionary<string, object>
            {
                ["goods_id"] = goodsId,
                ["page_sn"] = "10014",
                ["page_id"] = $"10014_{now}_{Random.Shared.NextInt64(1000000000, 9000000000)}",
                ["page_from"] = "35",
                ["page_version"] = "7",
                ["client_time"] = now.ToString(),
                ["refer_page_sn"] = "10002",
                ["refer_page_el_sn"] = "99862",
                ["phone_model"] = Device.Model,
                ["pic_w"] = 0,
                ["pic_h"] = 0,
                ["has_pic_url"] = 1,
                ["address_list"] = Array.Empty<object>(),
                ["extend_map"] = new Dictionary<string, object>(),
                ["_oak_rcto"] = "",
                ["union_pay_installed"] = true,
                ["client_lab"] = new Dictionary<string, string> { ["mall_h5_url_preload_enable"] = "1" },
                ["is_sys_minor"] = 0,
                ["system_language"] = "zh",
                ["impr_tips"] = Array.Empty<object>(),
                ["screen_height"] = Device.ScreenHeight,
                ["screen_width"] = Device.ScreenWidth,
                ["goods_detail_support_zoom"] = "true",
                ["pdd_goods_detail_dark_color_enable"] = true,
            };

            return await Http.PostFullAsync(url, body, BuildHeaders(antiToken: AntiTokenKind.Info2));
        }

        /// <summary>获取商品详情, 仅返回 body 字符串。</summary>
        public async Task<string> GetItemDetailAsync(string goodsId)
            => (await GetItemDetailFullAsync(goodsId)).Body;

        // ==================== 登录 (手机号 + 短信验证码) ====================
        //
        // 时序: [1] 请求短信验证码 (/api/oak/sigerus/mobile/code/request)
        //       [2] 提交验证码登录 (/api/oak/sigerus/login_mobile)
        //
        // fingerprint / touchevent 已实现 (GZIP+AES+RSA 信封, 明文由 DeviceProfile 构造):
        //   见 FingerprintBuilder / FingerprintCodec 与 docs/04_device_register/15_*。
        //   anti-token 走 info2(2af, AntiTokenKind.Info2), 与 fingerprint 共同构成登录风控数据。

        // 路径 (不含 query; x-p1 的 ul 用它, url 另拼 ?pdduid=)
        private const string PathSmsCodeRequest = "/api/sigerus/mobile/code/request";
        private const string PathLoginMobile = "/api/sigerus/login_mobile";

        /// <summary>
        /// 登录第一步: 请求短信验证码, 返回服务端完整响应。
        /// fingerprint/touchevent 由 DeviceProfile 构造 (同请求共用一把随机 key)。
        /// </summary>
        /// <param name="mobile">手机号</param>
        /// <param name="telCode">区号 (默认 86)</param>
        /// <param name="countryId">国家 id (默认 1=中国)</param>
        public async Task<HttpResult> LoginRequestSmsCodeAsync(
            string mobile, string telCode = "86", string countryId = "1")
        {
            var url = $"{ApiBase}{PathSmsCodeRequest}?pdduid=";
            long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            // fingerprint / touchevent: 同请求共用一把随机 key (与真机一致), 明文由 DeviceProfile 构造
            byte[] fpRandom = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(fpRandom);
            string fingerprint = FingerprintBuilder.BuildField(Device, nowMs, fpRandom);
            string touchevent = FingerprintBuilder.BuildTouchEventField(fpRandom);

            var body = new Dictionary<string, object>
            {
                ["request_times"] = 1,
                ["send_voice_code"] = false,
                ["mobile"] = mobile,
                ["touchevent"] = touchevent,
                ["country_id"] = countryId,
                ["tel_code"] = telCode,
                ["fingerprint"] = fingerprint,
                ["app_version"] = AppVersion,
                ["channel"] = "main_guanwang",
                ["platform"] = "2",
            };

            // body 序列化一次, 同一份原文既发送又作为 x-p1 的 bd 入参 (保证自签名自洽)
            string bodyJson = Newtonsoft.Json.JsonConvert.SerializeObject(body);
            var headers = BuildHeaders(antiToken: AntiTokenKind.Info2, xp1Path: PathSmsCodeRequest, xp1Body: bodyJson);

            var result = await Http.PostRawAsync(url, bodyJson, headers);
            Log.Info($"[登录·请求验证码] HTTP {(int)result.StatusCode}  body: {result.Body}");
            return result;
        }

        /// <summary>
        /// 第二步: 提交手机号 + 验证码完成登录。成功则回填 Session。
        /// (同样依赖 fingerprint; 需在拿到验证码后调用。)
        /// </summary>
        public async Task<HttpResult> LoginSubmitCodeAsync(
            string mobile, string code, string telCode = "86", string countryId = "1")
        {
            var url = $"{ApiBase}{PathLoginMobile}";   // login_mobile 无 ?pdduid= query
            long nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            byte[] fpRandom = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(fpRandom);
            string fingerprint = FingerprintBuilder.BuildField(Device, nowMs, fpRandom);
            string touchevent = FingerprintBuilder.BuildTouchEventField(fpRandom);

            // 字段顺序对齐样本 login_submit_code_example.txt
            var body = new Dictionary<string, object>
            {
                ["mobile"] = mobile,
                ["code"] = code,
                ["touchevent"] = touchevent,
                ["country_id"] = countryId,
                ["tel_code"] = telCode,
                ["login_app_id"] = 5,
                ["extra_vo"] = new Dictionary<string, object>(),
                ["support_enhance_type"] = 7,
                ["login_scene"] = "4",
                ["refer_page_sn"] = "10002",
                ["fingerprint"] = fingerprint,
                ["app_version"] = AppVersion,
                ["channel"] = "main_guanwang",
                ["platform"] = "2",
            };

            string bodyJson = System.Text.Json.JsonSerializer.Serialize(body);
            var headers = BuildHeaders(antiToken: AntiTokenKind.Info2, xp1Path: PathLoginMobile, xp1Body: bodyJson);

            var result = await Http.PostRawAsync(url, bodyJson, headers);
            Log.Info($"[登录·提交验证码] HTTP {(int)result.StatusCode}  body: {result.Body}");
            TryCaptureSession(result.Body);
            return result;
        }

        /// <summary>
        /// 完整登录: 发短信验证码 → 经委托获取验证码 → 提交登录 → 回填 Session。
        /// 验证码通过 <see cref="SmsCodeProvider"/> 委托获取 (实例化时注册, 满足不同接码场景)。
        /// </summary>
        public async Task<LoginResult> Login(string mobile, string telCode = "86", string countryId = "1")
        {
            //测试
            //this.Pddid = "oLkvgGln";
            // 1) 发短信验证码
            var send = await LoginRequestSmsCodeAsync(mobile, telCode, countryId);

            var sendJson = Newtonsoft.Json.JsonConvert.DeserializeObject<JObject>(send.Body);

            if (sendJson["verify_auth_token"] != null)
            {
                this.verifyAuthToken = sendJson["verify_auth_token"].ToString();
            }

            if (!send.Body.Contains("mobile_des"))
                return new LoginResult { Success = false, Stage = "send_code", Message = "发送验证码失败", SendCodeResponse = send };

            // 2) 经委托获取验证码
            if (SmsCodeProvider == null)
                throw new InvalidOperationException("未注册验证码委托 SmsCodeProvider, 无法完成登录 (构造 Android 时传入或事后赋值)。");
            string code = await SmsCodeProvider(new SmsCodeRequestContext
            {
                Mobile = mobile, TelCode = telCode, CountryId = countryId, SendCodeResponse = send
            });
            if (string.IsNullOrWhiteSpace(code))
                return new LoginResult { Success = false, Stage = "await_code", Message = "未获取到验证码", SendCodeResponse = send };

            // 3) 提交验证码登录
            var login = await LoginSubmitCodeAsync(mobile, code.Trim(), telCode, countryId);

            var result = Newtonsoft.Json.JsonConvert.DeserializeObject<JObject>(login.Body);

            var verifyToken = result["verify_auth_token"]?.ToString();

            if (!string.IsNullOrEmpty(verifyToken))
            {
                var verifyUrl = $"https://m.pinduoduo.net/psnl_verification.html?VerifyAuthToken={verifyToken}&type=highlayer&_x_hungary_module_id=lo_platform_login_benefit_wd";
            }

            if (login.StatusCode != System.Net.HttpStatusCode.OK || result["access_token"] == null)
            {
                Log.Info("[登录·提交验证码] 登录失败, Message: " + result["error_msg"]);
                return new LoginResult
                {
                    Success = false,
                    Stage = "login",
                    Message = "登录失败: " + result["error_msg"]?.ToString(),
                    SendCodeResponse = send,
                    LoginResponse = login,
                    Session = Session,
                };
            }

            //登录成功，回填 Session (access_token/uid 等)
            //{"uid":6598646341856,"uin":"","access_token":"","acid":"","mobile_id":"","mobile_des":"155****8540"}
            this.Session = new Session()
            {
                Uid = result.Value<long>("uid"),
                AccessToken = result.Value<string>("access_token"),
                Acid = result.Value<string>("acid"),
                MobileId = result.Value<string>("mobile_id"),
                MobileDes = result.Value<string>("mobile_des"),
            };

            return new LoginResult
            {
                Success = true,
                Stage = "login",
                Message = "登录成功",
                SendCodeResponse = send,
                LoginResponse = login,
                Session = Session,
            };
        }

        /// <summary>从登录响应尝试回填 Session (access_token/uid 等)。</summary>
        private void TryCaptureSession(string body)
        {
            if (string.IsNullOrEmpty(body)) return;
            var at = Regex.Match(body, "\"access_token\":\"([^\"]+)\"");
            if (at.Success) Session.AccessToken = at.Groups[1].Value;
            var uid = Regex.Match(body, "\"uid\":\"?(\\d+)\"?");
            if (uid.Success && long.TryParse(uid.Groups[1].Value, out var u)) Session.Uid = u;
        }
    }
}
