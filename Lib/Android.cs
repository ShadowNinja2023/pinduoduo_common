using System.Text.Encodings.Web;
using System.Text.RegularExpressions;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PddLib.Crypto;
using PddLib.H5;
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
    public class Android : IDisposable
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

        /// <summary>
        /// 登录 body 序列化选项: 宽松编码器, 避免默认 JavaScriptEncoder 把 +、非 ASCII 等转成 \uXXXX
        /// (与真机字节级对齐; 同一份字符串既发送又作 x-p1 的 bd 入参, 保证自签名自洽)。
        /// </summary>
        private static readonly System.Text.Json.JsonSerializerOptions JsonOpts = new()
        {
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        };

        private const string ApiBase = "https://api.pinduoduo.com";
        private const string AppVersion = "8.8.0";
        private const string AppBuildHash = "24f4a9fb4f113b97ad7e6958d27ee140996d17a7";
        private string verifyAuthToken = string.Empty;

        private readonly string? _proxyUrl;

        // ===== H5 web 加密 (anti_content / csr / encrypt_info) =====
        /// <summary>
        /// H5 常驻 Node 服务 (h5_service.js) 的完整路径。默认指向仓库脚本目录; 部署时按需覆盖。
        /// anti_content 采集面巨大 + csr 是自定义字节码 VM, 纯 C# 复刻不现实, 故走 Node 常驻服务。
        /// </summary>
        public static string H5ServiceJsPath { get; set; } =
            @"F:\TraceWorkspaces\拼多多全量分析\scripts\h5_tools\h5_service.js";

        /// <summary>懒加载的 H5 加密客户端 (常驻 Node 进程)。首次用时预热, 之后复用 (anti_content 高频)。</summary>
        private H5CryptoClient? _h5;
        private readonly SemaphoreSlim _h5InitLock = new(1, 1);
        private volatile bool _disposed;

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

        // ==================== H5 web 加密 (anti_content / csr / encrypt_info) ====================
        //
        // anti_content 是 PDD H5 商详 render 接口的风控 token ("0as..."), 生成需一整套浏览器指纹 (env)。
        // 本类按当前 mock 设备 (DeviceProfile) 派生自洽 env → 走常驻 Node 服务生成, 无需真机跑。

        /// <summary>
        /// 懒加载并预热 H5 加密客户端 (常驻 Node 服务)。首次调用等待 jsdom+VM 预热 (约 15~30s),
        /// 之后复用同一进程实例 (anti_content 可能高频调用)。线程安全。
        /// </summary>
        private async Task<H5CryptoClient> GetH5ClientAsync()
        {
            if (_h5 != null) return _h5;
            if (_disposed) throw new ObjectDisposedException(nameof(Android));
            await _h5InitLock.WaitAsync();
            try
            {
                if (_h5 == null)
                {
                    var c = new H5CryptoClient(H5ServiceJsPath);
                    await c.WaitReadyAsync(TimeSpan.FromSeconds(90));
                    _h5 = c;
                }
                return _h5;
            }
            finally { _h5InitLock.Release(); }
        }

        /// <summary>
        /// 基于当前 mock 设备指纹 (DeviceProfile) 构造 H5 anti_content 生成所需的浏览器环境 env。
        /// 采集面 = navigator / screen / webgl / 时区 等; 与 App 内 WebView 保持自洽 (UA 用 WebView 形态)。
        /// 返回匿名对象, 交给 H5CryptoClient 序列化 (字段名对齐 antiContentGen.hardenEnv 的扁平 dump 形态)。
        /// </summary>
        public object BuildH5Env()
        {
            // App 内 WebView 的 navigator.userAgent: 与 native BuildHeaders 的 UA 基座一致,
            // 去掉 phh_* 应用级后缀 (那些是 OkHttp header 层追加, 不在 navigator.userAgent 里)。
            string ua =
                $"Mozilla/5.0 (Linux; Android {Device.Osv}; {Device.Model} Build/{Device.BuildId}; wv) " +
                "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/143.0.7499.192 Mobile Safari/537.36";

            // navigator.deviceMemory 只暴露 0.25/0.5/1/2/4/8, 取不超过物理内存的最大档 (上限 8)
            double memGb = Device.TotalMemory / (1024.0 * 1024 * 1024);
            int dm = memGb >= 8 ? 8 : memGb >= 4 ? 4 : memGb >= 2 ? 2 : 1;

            // CSS 逻辑像素 = 物理像素 / devicePixelRatio
            double dpr = Device.Dpr > 0 ? Device.Dpr : 2.75;
            int cssW = (int)Math.Round(Device.ScreenWidth / dpr);
            int cssH = (int)Math.Round(Device.ScreenHeight / dpr);

            var (glVendor, glRenderer) = DeriveWebgl(Device.Soc);

            return new
            {
                ua,
                platform = "Linux armv81",
                lang = "zh-CN",
                langs = new[] { "zh-CN", "en-US", "zh", "en" },
                hc = Device.CpuCore > 0 ? Device.CpuCore : 8,
                dm,
                vendor = "Google Inc.",
                mtp = 5,
                appVersion = ua.Substring("Mozilla/".Length),
                product = "Gecko",
                screen = new { w = cssW, h = cssH, aw = cssW, ah = cssH, cd = 24, pd = 24 },
                dpr,
                tz = ParseTimeZoneId(Device.TimeZone),
                tzo = ParseTimeZoneOffsetMinutes(Device.TimeZone),
                plugins = Array.Empty<object>(),
                mimeTypes = Array.Empty<object>(),
                webgl = new { vendor = glVendor, renderer = glRenderer },
                hasChrome = true,
                webdriver = false,
            };
        }

        /// <summary>
        /// 生成 H5 anti_content 风控 token ("0as...")。首次调用预热 H5 服务, 之后复用同一进程。
        /// </summary>
        /// <param name="env">浏览器指纹 env 覆盖; 传 null 用 <see cref="BuildH5Env"/> 从当前设备派生。</param>
        public async Task<string> GetAntiContentAsync(object? env = null)
        {
            //return "0asWfqnFpioyj9vxknP4PpgU1UWNI1v9oirccirc96Ojg-ny5T-Dv5r76mNgUdsd8KrputvVTBf0TMfUD3NV4PR2vfXUPxN4aVK-wVeFl3a1EnR3xr1zOI-vhv-7kW0KFUYZLPe4_MQdEMqB_sMZpZngUNEV5Pt6Yof84FqANquqXjMnkS_67C1SXikcI12_buBVKpREMV0vZzDtUTf10IynBZeynpd3ABV5Ds1rT_-j3CK31lHBjio6A304FPDvZ7A_KIOLViFpsws1z_wW8coiQS6MqcJxzCSc3udq8rOkaSJaz6qVKWZt8I42t1c6OREWN0eDHt82aeMv1wB6kZY6oI5ueaXTAgF7DB4fX-re6Bx4bay0A-Y3HzbP7KP4yV6jAmZbtZi6bwNxF4pU7CfGZ5qGlAfGtIm_dvV_qPMqhKMwO2gaTtzTARAh2MdUV21g0Um-Ors-Ov4xZoNmNSrvaaZ1FOggRfp0ycgBdcgj1Mlz2zUPMXMtEp5ghkAKRoItP8Wx-GongxQ-InyA2KSYH0oQvQY6MHJLyBHyWXUpoKSHdrmRWLlU5ZwnwzoQIx1-JCHC6kagtzSF3-xnUV8FYKCPMnDIJyKCqqdUi3tUYrcpjydE0Dr5NfD8zbSEd5AkcaXlbclShAsSPA3bEWcIGha833-hrMAHNPaLUwclRRLEyHCqcNH-zdL7NKv-UWFN9d";
            var client = await GetH5ClientAsync();
            return await client.GetAntiContentAsync(env ?? BuildH5Env());
        }

        /// <summary>生成 H5 混合加密的 {csr_risk_token, rawKey, rawIV} (复用同一 H5 服务实例)。</summary>
        public async Task<H5CryptoClient.KeyIvCsr> GetH5KeyIvCsrAsync()
            => await (await GetH5ClientAsync()).GetKeyIvCsrAsync();

        /// <summary>用 rawKey/rawIV 解密响应 encrypt_info (AES-256-CBC, 复用同一 H5 服务实例)。</summary>
        public async Task<string?> DecryptH5EncryptInfoAsync(string encryptInfo, string rawKey, string rawIV)
            => await (await GetH5ClientAsync()).DecryptEncryptInfoAsync(encryptInfo, rawKey, rawIV);

        /// <summary>由 SoC 型号派生 WebGL vendor/renderer (与真机 GPU 自洽; 无法精确匹配时按厂商回落)。</summary>
        private static (string vendor, string renderer) DeriveWebgl(string? soc)
        {
            string up = (soc ?? "").Trim().ToUpperInvariant();

            // Qualcomm Snapdragon (SM#### / SDM#### / QCS / 含 SNAPDRAGON)
            if (up.StartsWith("SM") || up.StartsWith("SDM") || up.StartsWith("QCS") || up.Contains("SNAPDRAGON"))
            {
                string adreno =
                    up.StartsWith("SM8750") ? "Adreno (TM) 830" :
                    up.StartsWith("SM8650") ? "Adreno (TM) 750" :
                    up.StartsWith("SM8550") ? "Adreno (TM) 740" :
                    up.StartsWith("SM8475") || up.StartsWith("SM8450") ? "Adreno (TM) 730" :
                    up.StartsWith("SM8350") ? "Adreno (TM) 660" :
                    up.StartsWith("SM7") ? "Adreno (TM) 710" :
                    up.StartsWith("SM6") ? "Adreno (TM) 619" :
                    "Adreno (TM) 640";
                return ("Google Inc. (Qualcomm)", $"ANGLE (Qualcomm, {adreno}, OpenGL ES 3.2)");
            }
            // MediaTek (MT#### / Dimensity / Helio)
            if (up.StartsWith("MT") || up.Contains("DIMENSITY") || up.Contains("HELIO"))
                return ("Google Inc. (ARM)", "ANGLE (ARM, Mali-G715, OpenGL ES 3.2)");
            // Samsung Exynos
            if (up.StartsWith("EXYNOS") || up.StartsWith("S5E"))
                return ("Google Inc. (ARM)", "ANGLE (ARM, Mali-G78, OpenGL ES 3.2)");
            // 回落: 通用 Adreno (Qualcomm 覆盖面最广)
            return ("Google Inc. (Qualcomm)", "ANGLE (Qualcomm, Adreno (TM) 640, OpenGL ES 3.2)");
        }

        /// <summary>从 DeviceProfile.TimeZone ("Asia/Shanghai GMT+08:00") 取 IANA 时区 id。</summary>
        private static string ParseTimeZoneId(string? tz)
        {
            if (string.IsNullOrWhiteSpace(tz)) return "Asia/Shanghai";
            int sp = tz.IndexOf(' ');
            return sp > 0 ? tz.Substring(0, sp) : tz;
        }

        /// <summary>
        /// 从 TimeZone 尾部 "GMT+08:00" 解析 JS getTimezoneOffset() 语义的分钟偏移 (东区为负, 东八区 = -480)。
        /// </summary>
        private static int ParseTimeZoneOffsetMinutes(string? tz)
        {
            var m = Regex.Match(tz ?? "", @"GMT([+-])(\d{2}):?(\d{2})");
            if (!m.Success) return -480;
            int sign = m.Groups[1].Value == "+" ? 1 : -1;
            int h = int.Parse(m.Groups[2].Value);
            int mm = int.Parse(m.Groups[3].Value);
            return -sign * (h * 60 + mm);
        }

        // ==================== 业务接口 (注册后复用同一设备/pddid) ====================

        /// <summary>
        /// 构建业务公共请求头 (基于已注册的 DeviceProfile + pddid)。
        /// </summary>
        /// <param name="extra">追加/覆盖的自定义头</param>
        /// <param name="antiToken">anti-token 类型 (None/Info4/Info2, 互斥)</param>
        /// <param name="xp1Path">非空则生成 x-p1 (对 body 的自签名), ul 取该请求路径</param>
        /// <param name="xp1Body">x-p1 的 bd 入参 = 本请求实际发送的 body JSON 原文</param>
        private async Task<Dictionary<string, string>> BuildHeaders(Dictionary<string, string>? extra = null,
            AntiTokenKind antiToken = AntiTokenKind.None,
            string? xp1Path = null, string? xp1Body = null, bool useAntiContent = false,string referer = "Android")
        {
            string ua =
                $"android Mozilla/5.0 (Linux; Android {Device.Osv}; {Device.Model} Build/{Device.BuildId}; wv) " +
                "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/143.0.7499.192 Safari/537.36 " +
                $" phh_android_version/{AppVersion} phh_android_build/{AppBuildHash}" +
                " phh_android_channel/main_guanwang pversion/0";

            string dpr = Device.Dpr > 0 ? Device.Dpr.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture) : "";
            string queries =
                $"width={Device.ScreenWidth}&height={Device.ScreenHeight}" +
                (dpr.Length > 0 ? $"&dpr={dpr}" : "") +
                $"&net=1&brand={Device.Brand}" +
                $"&model={Device.Model}&osv={Device.Osv}&appv={AppVersion}&pl=2";

            var headers = new Dictionary<string, string>
            {
                ["etag"] = Pddid,
                ["referer"] = referer,
                ["content-type"] = "application/json;charset=UTF-8",
                ["user-agent"] = ua,
                ["accept-encoding"] = "gzip",
                ["accept-language"] = "zh-Hans-CN",
                ["p-appname"] = "pinduoduo",
                ["p-mediainfo"] = "player=1.0.3&rtc=1.0.0",
                ["p-proc"] = "main",
                ["x-app-lang"] = "zh",
                ["x-client-language"] = "zh",
                ["x-client-region"] = "1",
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
                    serverId: Pddid,   // ★ info4(2ag) 明文须绑定 pddid(=etag) 作 serverId; 真机 anti-token 解出即为此值。空则服务端判无归属请求→硬风控。
                    uuid: Guid.TryParse(Device.Uuid, out var g) ? g : Guid.NewGuid());
                headers["anti-token"] = Info4Codec.Encrypt(pt);
            }
            else if (antiToken == AntiTokenKind.Info2)
            {
                headers["anti-token"] = Info2Builder.BuildAntiToken(Device, nowMs);
            }

            if (useAntiContent)
            {
                headers["anti-content"] = await GetAntiContentAsync();
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

        /// <summary>
        /// 获取商品详情 (integration/render), 返回完整 HTTP 结果。
        /// <paramref name="antiToken"/> 可切换测试: 真机 render 用 Info4(2ag); 排查风控时可传 Info2/None 对照。
        /// </summary>
        public async Task<HttpResult> GetItemDetailFullAsync(string goodsId, AntiTokenKind antiToken = AntiTokenKind.Info4)
        {
            var url = $"{ApiBase}/api/oak/integration/render?pdduid={Session.Uid}";
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var body = new Dictionary<string, object>
            {
                ["address_list"] = Array.Empty<object>(),
                ["page_sn"] = "10014",
                ["page_id"] = $"10014_{now}_{Random.Shared.NextInt64(1000000000, 9000000000)}",
                ["goods_id"] = goodsId,
                ["phone_model"] = Device.Model,
                ["page_from"] = "35",
                ["page_version"] = "7",
                ["client_time"] = now.ToString(),
                ["refer_page_sn"] = "10002",
                ["refer_page_el_sn"] = "99862",
                ["pic_w"] = 0,
                ["pic_h"] = 0,
                ["has_pic_url"] = 1,
                ["extend_map"] = new Dictionary<string, object>() { },
                ["_oak_gallery_token"] = "",
                ["_oak_gallery"] = "",
                ["_oak_rcto"] = "",

                ["union_pay_installed"] = false,
                ["client_lab"] = new Dictionary<string, string> { ["mall_h5_url_preload_enable"] = "1" },
                ["is_sys_minor"] = 0,
                ["system_language"] = "zh",
                ["impr_tips"] = Array.Empty<object>(),
                ["screen_height"] = Device.ScreenHeight,
                ["screen_width"] = Device.ScreenWidth,
                ["goods_detail_support_zoom"] = "true",
                ["pdd_goods_detail_dark_color_enable"] = true,
            };

            var result =  await Http.PostFullAsync(url, body, await BuildHeaders(antiToken: antiToken));

            var resultJson = JsonConvert.DeserializeObject<JObject>(result.Body);

            if (resultJson["redirect_url"] != null)
            {
                // ★ 原生 render 返回 redirect_url 是正常两段式流程 (非失败): 服务端在此 URL 里
                //   现签发本次会话的风控归因 token (_oak_rcto / _oak_gallery_token, 响应头 collect-oak-rcto:1)。
                //   H5 render 必须把这些 token 原样带回, 否则服务端判无有效曝光来源 → 硬风控。
                string redirectPath = resultJson["redirect_url"]!.ToString();   // "goods.html?...&_oak_rcto=..."
                var redirectUrl = $"https://m.pinduoduo.net/{redirectPath}";

                //添加必要cookie
                Http.handler.CookieContainer.Add(new Uri("https://m.pinduoduo.net"), new System.Net.Cookie("pdd_user_id", this.Session.Uid.ToString()));
                Http.handler.CookieContainer.Add(new Uri("https://m.pinduoduo.net"), new System.Net.Cookie("PDDAccessToken", this.Session.AccessToken.ToString()));
                Http.handler.CookieContainer.Add(new Uri("https://m.pinduoduo.net"), new System.Net.Cookie("ETag", this.Pddid));
                Http.handler.CookieContainer.Add(new Uri("https://m.pinduoduo.net"), new System.Net.Cookie("pdd_user_uin", this.Session.Uin.ToString()));
                Http.handler.CookieContainer.Add(new Uri("https://m.pinduoduo.net"), new System.Net.Cookie("install_token", this.Device.InstallToken));

                var get = await Http.GetFullAsync(redirectUrl);

                var rp = ParseQuery(redirectPath);
                string Rp(string k, string dflt = "") => rp.TryGetValue(k, out var v) && v.Length > 0 ? v : dflt;

                now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
                var csr = await GetH5KeyIvCsrAsync();

                // body 类型对齐真机 H5 render: page_version/goods_id/page_from/page_sn 为数字, refer_page_* 为字符串
                body = new Dictionary<string, object>
                {
                    ["page_version"] = 7,
                    ["goods_id"] = long.Parse(goodsId),
                    ["page_from"] = 35,
                    ["hostname"] = "m.pinduoduo.net",
                    ["client_time"] = now,
                    ["refer_page_sn"] = "10002",
                    ["refer_page_el_sn"] = "99862",
                    ["extend_map"] = new { _oc_from_redirect = "1" },

                    ["page_sn"] = 10014,
                    ["page_id"] = $"10014_{now}_{Utils.GetRandomChars(10).ToLower()}",
                    ["_oak_gallery"] = "",
                    ["_oc_from_redirect"] = "1",

                    ["_oak_rcto"] = "",
                    ["_oak_gallery_token"] = "",

                    ["anti_content"] = await GetAntiContentAsync(),

                    ["front_supports"] = new string[]
                    {
                        "community_purchase",
                        "split_info_section",
                        "render_opt_2022",
                        "new_price_bottom",
                        "group_tip_end_time",
                        "custom_sku",
                        "goods_reminder",
                        "morgan_suffix",
                        "goods_reminder_click",
                    },
                    ["csr_risk_token"] = csr.CsrRiskToken,
                };

                var extra = new Dictionary<string, string>()
                {
                    ["p-mode"] = "",
                    ["multi-set"] = "1,1,100000824",
                    ["x-yak-llt"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString(),
                    ["accept"] = "application/json, text/plain, */*",
                };

                result = await Http.PostFullAsync(url, body, await BuildHeaders(extra,antiToken: AntiTokenKind.Info4, useAntiContent: true,referer: redirectUrl));

                resultJson = JsonConvert.DeserializeObject<JObject>(result.Body);

                if (resultJson["verify_auth_token"] != null)
                {
                    this.verifyAuthToken = resultJson["verify_auth_token"].ToString();
                }

            }


            return result;
        }

        /// <summary>获取商品详情, 仅返回 body 字符串。</summary>
        public async Task<string> GetItemDetailAsync(string goodsId, AntiTokenKind antiToken = AntiTokenKind.Info4)
            => (await GetItemDetailFullAsync(goodsId, antiToken)).Body;

        // ==================== 搜索 (/search) ====================

        /// <summary>
        /// 关键词搜索商品 (POST /search)。用于业务态风控测试。
        /// 字段对齐样本 examples/business_example/search.txt; anti-token 走 info2(2af, 该样本形态)。
        /// </summary>
        /// <param name="keyword">搜索词 (如 "牙刷")</param>
        /// <param name="page">页码 (从 1 起)</param>
        /// <param name="size">每页数量</param>
        public async Task<HttpResult> SearchFullAsync(string keyword, int page = 1, int size = 20)
        {
            var url = $"{ApiBase}/search?source=index&pdduid={Session.Uid}";

            var body = new Dictionary<string, object?>
            {
                ["install_token"] = Device.InstallToken,
                ["item_ver"] = "lzqq",
                ["list_id"] = RandBase62(8),                 // 本次列表会话 id
                ["track_data"] = $"refer_page_id,10002_{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}_{Random.Shared.NextInt64(1000000000, 9000000000)};refer_search_met_pos,12",
                ["search_met"] = "hot",
                ["sort"] = "default",
                ["source"] = "index",
                ["is_sys_minor"] = "0",
                ["is_page_init"] = "1",
                ["q"] = keyword,
                ["page_sn"] = "10015",
                ["page_id"] = "search_result.html",
                ["size"] = size.ToString(),
                ["referer_params"] = null,
                ["union_pay_installed"] = "0",
                ["show_mark_icon"] = "1",
                ["q_search"] = "{\"pes_req_id\":\"" + Guid.NewGuid().ToString() + "\"}",
                ["requery"] = "0",
                ["page"] = page.ToString(),
                ["engine_version"] = "2.0",
                ["is_new_query"] = "1",
                ["back_search"] = "false",
            };

            var result = await Http.PostFullAsync(url, body, await BuildHeaders(antiToken: AntiTokenKind.Info2));
            Log.Info($"[搜索] q={keyword} HTTP {(int)result.StatusCode}  body: {result.Body}");
            return result;
        }

        /// <summary>关键词搜索, 仅返回 body 字符串。</summary>
        public async Task<string> SearchAsync(string keyword, int page = 1, int size = 20)
            => (await SearchFullAsync(keyword, page, size)).Body;

        private const string Base62Chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        /// <summary>生成 n 位 base62 随机串 (用于 list_id 等不透明客户端 id)。</summary>
        private static string RandBase62(int n)
        {
            var sb = new System.Text.StringBuilder(n);
            for (int i = 0; i < n; i++) sb.Append(Base62Chars[Random.Shared.Next(Base62Chars.Length)]);
            return sb.ToString();
        }

        /// <summary>把 URL(或 "path?query") 的 query 解析成键值字典 (值已 URL 解码)。</summary>
        private static Dictionary<string, string> ParseQuery(string url)
        {
            var d = new Dictionary<string, string>(StringComparer.Ordinal);
            if (string.IsNullOrEmpty(url)) return d;
            int q = url.IndexOf('?');
            string qs = q >= 0 ? url.Substring(q + 1) : url;
            foreach (var pair in qs.Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = pair.IndexOf('=');
                string k = eq >= 0 ? pair.Substring(0, eq) : pair;
                string v = eq >= 0 ? pair.Substring(eq + 1) : "";
                d[Uri.UnescapeDataString(k)] = Uri.UnescapeDataString(v);
            }
            return d;
        }

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
            var headers = await BuildHeaders(antiToken: AntiTokenKind.Info2, xp1Path: PathSmsCodeRequest, xp1Body: bodyJson);

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

            string bodyJson = System.Text.Json.JsonSerializer.Serialize(body, JsonOpts);
            var headers = await BuildHeaders(antiToken: AntiTokenKind.Info2, xp1Path: PathLoginMobile, xp1Body: bodyJson);

            var result = await Http.PostRawAsync(url, bodyJson, headers);
            Log.Info($"[登录·提交验证码] HTTP {(int)result.StatusCode}  body: {result.Body}");
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
                Uin = result.Value<string>("uin")
            };

            // ★ 登录后账号↔设备绑定/定时上报 (meta_type=all, scene=4, 带 uid)。
            //   真机登录后 + 之后定时都会发; 缺这步 → 服务端视为"账号+未绑定设备"→ render 等业务降级(售罄)。
            await ReportMetaInfoAsync();

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

        /// <summary>
        /// 账号↔设备 meta_info 上报 (meta_type=all, scene=4, 带 uid)。
        /// 真机在登录后 + 之后定时都会发, 用于把账号绑定到设备并维持会话活跃;
        /// 缺失会导致业务接口(如 render)对该"账号+设备"组合降级(售罄)。
        ///
        /// 参数从 <see cref="Session"/> 取; 未登录(Session.Uid==0 或无 pddid)则直接跳过、不上报。
        /// 业务侧可在需要"保活/续绑"时手动调用 (无需内建定时)。
        /// </summary>
        /// <returns>true=已上报; false=未登录跳过。</returns>
        public async Task<bool> ReportMetaInfoAsync()
        {
            if (Session == null || Session.Uid == 0 || string.IsNullOrEmpty(Pddid))
                return false;
            try
            {
                await Register.SendSigninMetaAsync(Pddid, Session.Uid, Session.AccessToken ?? string.Empty);
                return true;
            }
            catch (Exception ex)
            {
                Log.Info("[meta 上报] 失败(不阻断): " + ex.Message);
                return false;
            }
        }

        // ==================== 状态持久化 (设备 + 会话 + pddid + cookie) ====================

        /// <summary>
        /// 把当前设备指纹 + 登录会话 + pddid + cookie 序列化到磁盘, 供后续测试复用
        /// (免去每次重新注册/登录, 并保持服务端会话连续性: api_uid/acid 等 cookie 一并保存)。
        /// </summary>
        public void SaveState(string path)
        {
            var state = new AndroidState
            {
                Device = Device,
                Session = Session,
                Pddid = Pddid,
                VerifyAuthToken = verifyAuthToken,
                SavedAt = DateTimeOffset.UtcNow,
            };
            foreach (System.Net.Cookie c in Cookies.GetAllCookies())
                state.Cookies.Add(new AndroidState.CookieItem
                {
                    Name = c.Name,
                    Value = c.Value,
                    Domain = c.Domain,
                    Path = string.IsNullOrEmpty(c.Path) ? "/" : c.Path,
                });

            var json = System.Text.Json.JsonSerializer.Serialize(state,
                new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
            var dir = System.IO.Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) System.IO.Directory.CreateDirectory(dir);
            System.IO.File.WriteAllText(path, json);
        }

        /// <summary>是否存在持久化状态文件。</summary>
        public static bool StateExists(string path) => System.IO.File.Exists(path);

        /// <summary>
        /// 从磁盘加载已注册/登录的设备状态, 重建 Android 实例 (不重新注册/登录)。
        /// cookie(api_uid/acid 等) 一并恢复到共享 CookieContainer, 保持服务端会话连续。
        /// </summary>
        public static Android LoadState(string path, string? proxyUrl = null,
            string? proxyUsername = null, string? proxyPassword = null, SmsCodeHandler? smsCodeProvider = null)
        {
            var json = System.IO.File.ReadAllText(path);
            var state = System.Text.Json.JsonSerializer.Deserialize<AndroidState>(json)
                ?? throw new InvalidOperationException("状态文件解析失败: " + path);

            var a = new Android(state.Device ?? new DeviceProfile(), proxyUrl, proxyUsername, proxyPassword, smsCodeProvider);
            a.Session = state.Session ?? new Session();
            a.Pddid = state.Pddid ?? string.Empty;
            a.verifyAuthToken = state.VerifyAuthToken ?? string.Empty;
            foreach (var c in state.Cookies)
            {
                try { a.Cookies.Add(new System.Net.Cookie(c.Name, c.Value, string.IsNullOrEmpty(c.Path) ? "/" : c.Path, c.Domain)); }
                catch { /* 个别 cookie 域非法则忽略 */ }
            }
            return a;
        }

        /// <summary>释放常驻 H5 Node 服务进程 (若已启动) 等资源。</summary>
        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try { _h5?.Dispose(); } catch { }
            try { _h5InitLock.Dispose(); } catch { }
        }
    }

    /// <summary>Android 可持久化状态: 设备指纹 + 会话 + pddid + cookie。</summary>
    public sealed class AndroidState
    {
        public DeviceProfile Device { get; set; } = new();
        public Session Session { get; set; } = new();
        public string Pddid { get; set; } = string.Empty;
        public string VerifyAuthToken { get; set; } = string.Empty;
        public DateTimeOffset SavedAt { get; set; }
        public List<CookieItem> Cookies { get; set; } = new();

        public sealed class CookieItem
        {
            public string Name { get; set; } = string.Empty;
            public string Value { get; set; } = string.Empty;
            public string Domain { get; set; } = string.Empty;
            public string Path { get; set; } = "/";
        }
    }
}
