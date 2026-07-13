using System.Text;
using System.Text.RegularExpressions;
using PddLib.Register;

// ============================================================
// mock 设备端到端发送测试 (向 PDD 生产服务器发报文)
//
//   用法:
//     dotnet run --project SendTest -- [count]            批量 01 独立性测试
//     dotnet run --project SendTest -- seq                单台设备完整时序 01→02→03→05
//     (可在末尾追加 proxyUrl, 如 http://127.0.0.1:8888 挂抓包)
//
//   ⚠ dotnet run 传参易被吞, 建议直接跑 exe:
//     SendTest.exe 3                 批量 3 台
//     SendTest.exe seq               单台走时序
//     SendTest.exe seq http://127.0.0.1:8888
//
//   验证目标 (NEXT_SESSION 步骤 2/3/4):
//     - mock 设备发 01 → 服务端是否下发"新" pdd_id (而非样本的 WqfIGg5r)
//     - 复用该 pddid 走 02/03/05 → 各步 HTTP 状态与服务端反馈
//
//   安全: 仅用于授权的逆向研究与自有设备注册联调。
// ============================================================

Console.OutputEncoding = Encoding.UTF8;

if (args.Length > 0 && args[0].Equals("seq", StringComparison.OrdinalIgnoreCase))
{
    string? seqProxy = args.Length > 1 ? args[1] : null;
    await RunSequence(seqProxy);
    return;
}

if (args.Length > 0 && args[0].Equals("v06", StringComparison.OrdinalIgnoreCase))
{
    Verify06Structure();
    return;
}

// 设备库网关实测: SendTest.exe dev <baseUrl> <apiKey> <apiSecret> [ms|sec]
if (args.Length > 0 && args[0].Equals("dev", StringComparison.OrdinalIgnoreCase))
{
    await TestGetRandomDevice(args);
    return;
}

// 淘宝设备 → PDD 基准转换: SendTest.exe conv <baseUrl> <apiKey> <apiSecret>
if (args.Length > 0 && args[0].Equals("conv", StringComparison.OrdinalIgnoreCase))
{
    await TestConvert(args);
    return;
}

// 淘宝设备 → 转 mock → 发 01: SendTest.exe dev01 <baseUrl> <apiKey> <apiSecret> [count] [proxyUrl]
if (args.Length > 0 && args[0].Equals("dev01", StringComparison.OrdinalIgnoreCase))
{
    await TestDev01(args);
    return;
}

// 淘宝设备 → 转 mock → 完整时序 01→02→03→04→05→06: SendTest.exe devseq <baseUrl> <apiKey> <apiSecret> [proxyUrl]
if (args.Length > 0 && args[0].Equals("devseq", StringComparison.OrdinalIgnoreCase))
{
    await TestDevSeq(args);
    return;
}

// Android.CreateNewAsync 端到端 (网关凭据内置): SendTest.exe android [proxyUrl]
if (args.Length > 0 && args[0].Equals("android", StringComparison.OrdinalIgnoreCase))
{
    string? p = args.Length > 1 ? args[1] : null;
    Console.WriteLine("=== Android.CreateNewAsync (取淘宝设备→转mock→01~08注册) ===\n");
    try
    {
        var android = await PddLib.Android.CreateNewAsync(p);
        Console.WriteLine($"[注册成功] pddid={android.Pddid}");
        var jar = android.Cookies.GetCookies(new Uri("https://api.pinduoduo.com"));
        Console.WriteLine($"  CookieContainer 数量={jar.Count}: {string.Join("; ", jar.Select(c => $"{c.Name}={c.Value}"))}");
        Console.WriteLine($"  机型={android.Device.Brand}/{android.Device.Model} osv={android.Device.Osv} build={android.Device.BuildId}");
        Console.WriteLine($"  android_id={android.Device.AndroidId} oaid={android.Device.Oaid}");
        Console.WriteLine($"  uuid={android.Device.Uuid}  p47={android.Device.P47}");
        Console.WriteLine($"  api_uid(cookie)={(string.IsNullOrEmpty(android.Device.HeaderApiUid) ? "(无)" : android.Device.HeaderApiUid)}");
    }
    catch (Exception ex) { Console.WriteLine($"[失败] {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}"); }
    return;
}

// 临时: 用 .NET GZipStream 验证 2af anti-token 解密+解压: SendTest.exe afdec
if (args.Length > 0 && args[0].Equals("afdec", StringComparison.OrdinalIgnoreCase))
{
    AfDecodeTest();
    return;
}

// 临时: 从 DeviceProfile 构造 info2 TLV 并与样本逐字段对照: SendTest.exe afbuild
if (args.Length > 0 && args[0].Equals("afbuild", StringComparison.OrdinalIgnoreCase))
{
    AfBuildTest();
    return;
}

// 临时: 解 fingerprint/touchevent + 从 DeviceProfile 构造对照: SendTest.exe fpbuild
if (args.Length > 0 && args[0].Equals("fpbuild", StringComparison.OrdinalIgnoreCase))
{
    FpBuildTest();
    return;
}

// 第一次尝试登录 (注册设备 → 请求短信验证码): SendTest.exe login <手机号> [proxyUrl]
if (args.Length > 0 && args[0].Equals("login", StringComparison.OrdinalIgnoreCase))
{
    await TestLogin(args);
    return;
}

int count = args.Length > 0 && int.TryParse(args[0], out int c) ? c : 1;
string? proxy = args.Length > 1 ? args[1] : null;

Console.WriteLine($"=== mock 设备端到端发送 (count={count}{(proxy != null ? $", proxy={proxy}" : "")}) ===");
Console.WriteLine("目标: api.pinduoduo.com /project/meta_info  (01 报文, scene=1)\n");

var pddIds = new List<string>();

for (int i = 0; i < count; i++)
{
    var dev = DeviceMocker.NewDevice();
    var client = new RegisterClient(dev, proxy);   // UseCapturedKey=false: 真随机 key + 新版 RSA 公钥

    Console.WriteLine($"---- 设备 #{i} ----");
    Console.WriteLine($"  android_id = {dev.AndroidId}");
    Console.WriteLine($"  uuid       = {dev.Uuid}");
    Console.WriteLine($"  p47        = {dev.P47}");
    Console.WriteLine($"  oaid       = {dev.Oaid}");

    try
    {
        var resp = await client.Send01Async();
        string body = resp.Body;
        string pddId = Match(body, "\"pdd_id\":\"([^\"]+)\"");
        bool hasExt = body.Contains("\"ext_data\"");
        bool isSampleId = pddId == "WqfIGg5r";

        Console.WriteLine($"  HTTP {(int)resp.StatusCode}  etag(resp)={resp.Etag ?? "(无)"}");
        Console.WriteLine($"  pdd_id   = {(pddId.Length > 0 ? pddId : "(无)")}" +
                          $"{(isSampleId ? "  ⚠ 与样本相同(WqfIGg5r), 未被当新设备" : "")}");
        Console.WriteLine($"  ext_data = {(hasExt ? "有" : "无")}");
        string bodyShort = body.Length > 240 ? body[..240] + "…" : body;
        Console.WriteLine($"  body({body.Length}): {bodyShort}");

        if (pddId.Length > 0) pddIds.Add(pddId);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  异常: {ex.GetType().Name}: {ex.Message}");
    }
    Console.WriteLine();
}

Console.WriteLine("=== 汇总 ===");
Console.WriteLine($"成功取得 pdd_id: {pddIds.Count}/{count}");
if (pddIds.Count > 0)
{
    int uniq = new HashSet<string>(pddIds).Count;
    int sampleHits = pddIds.FindAll(x => x == "WqfIGg5r").Count;
    Console.WriteLine($"  互不相同      : {uniq}/{pddIds.Count} {(uniq == pddIds.Count ? "PASS (每台独立新设备)" : "⚠ 有重复")}");
    Console.WriteLine($"  非样本 pdd_id : {(sampleHits == 0 ? "PASS (均为新下发)" : $"⚠ {sampleHits} 台回显样本 WqfIGg5r")}");
    Console.WriteLine($"  pdd_id 列表   : {string.Join(", ", pddIds)}");
}
else
{
    Console.WriteLine("  未取得任何 pdd_id, 见上方各设备响应/异常排查。");
}

// ============================================================
// 临时验证: 2af anti-token = '2af' + base64(AES-128-CBC(gzip(TLV)))
//   key=pdd_aes_180121_1, IV=00..03。用 .NET GZipStream 解压 (换实现验证)。
// ============================================================
static void AfDecodeTest()
{
    const string path = @"f:\TraceWorkspaces\拼多多全量分析\examples\login_send_code_example.txt";
    var m = Regex.Match(File.ReadAllText(path), @"^anti-token:\s*(\S+)\s*$", RegexOptions.Multiline);
    string anti = m.Groups[1].Value;
    Console.WriteLine($"=== info2 (2af) anti-token 解码/往返验证 ===");
    Console.WriteLine($"anti-token 长度={anti.Length} 前缀={anti[..3]}\n");

    // 1) 解密 (Info2Codec)
    byte[] tlv = PddLib.Crypto.Info2Codec.Decrypt(anti);
    Console.WriteLine($"[解密] TLV 明文 {tlv.Length} 字节, magic={Convert.ToHexString(tlv[..4])} total={(tlv[4] << 8) | tlv[5]}");

    // 2) 解析帧
    var parsed = PddLib.Crypto.Info2Tlv.Parse(tlv);
    Console.WriteLine($"[解析] {parsed.Entries.Count} 条目:");
    foreach (var e in parsed.Entries)
    {
        int il = e.Value.Length >= 1 ? e.Value[0] : -1;
        string shown;
        if (il == e.Value.Length - 1 && il >= 0)
        {
            byte[] inner = e.Value[1..];
            bool printable = inner.Length > 0 && Array.TrueForAll(inner, b => b >= 32 && b < 127);
            shown = printable ? $"\"{System.Text.Encoding.UTF8.GetString(inner)}\""
                              : (inner.Length == 0 ? "(空)" : "0x" + Convert.ToHexString(inner));
        }
        else shown = "(复合/raw len=" + e.Value.Length + ")";
        Console.WriteLine($"    grp={e.Group:x2} idx={e.Index:x2}  {shown}");
    }

    // 3) 重建帧, 应与解密明文逐字节一致
    byte[] rebuilt = parsed.Build();
    bool frameSame = rebuilt.AsSpan().SequenceEqual(tlv);
    Console.WriteLine($"\n[帧往返] 重建 {rebuilt.Length} 字节, 与原始一致: {(frameSame ? "PASS" : "FAIL")}");
    if (!frameSame)
    {
        int d = 0; while (d < Math.Min(rebuilt.Length, tlv.Length) && rebuilt[d] == tlv[d]) d++;
        Console.WriteLine($"    首个差异 @{d}");
    }

    // 4) 加密往返: TLV → Encrypt → Decrypt == TLV (gzip 字节可不同, 明文须一致)
    string reAnti = PddLib.Crypto.Info2Codec.Encrypt(tlv);
    byte[] tlv2 = PddLib.Crypto.Info2Codec.Decrypt(reAnti);
    bool cryptoSame = tlv2.AsSpan().SequenceEqual(tlv);
    Console.WriteLine($"[加密往返] Encrypt→Decrypt 明文一致: {(cryptoSame ? "PASS" : "FAIL")}  (重出 anti-token 长度={reAnti.Length})");
}

// ============================================================
// 解样本 fingerprint/touchevent(固定key) + 从 DeviceProfile 构造并逐字段对照。
// ============================================================
static void FpBuildTest()
{
    const string path = @"f:\TraceWorkspaces\拼多多全量分析\examples\login_send_code_example.txt";
    string text = File.ReadAllText(path);
    string bodyStr = text[text.IndexOf("{\"request_times")..];
    using var outer = System.Text.Json.JsonDocument.Parse(bodyStr);
    string fpPkt = outer.RootElement.GetProperty("fingerprint").GetString()!;
    string tePkt = outer.RootElement.GetProperty("touchevent").GetString()!;
    byte[] fixedKey = PddLib.Crypto.FingerprintCodec.FixedAesKey();

    string sampleFp = PddLib.Crypto.FingerprintCodec.Decrypt(fpPkt, fixedKey);
    string sampleTe = PddLib.Crypto.FingerprintCodec.Decrypt(tePkt, fixedKey);
    Console.WriteLine("=== 样本解密 (固定 key) ===");
    Console.WriteLine($"touchevent: {sampleTe}");
    Console.WriteLine($"fingerprint ({sampleFp.Length}B): {sampleFp[..Math.Min(200, sampleFp.Length)]}...\n");

    // 造与样本一致的设备
    var d = PddLib.Register.DeviceProfile.FromSample01();
    d.Sno = "unknown"; d.Brand = "Lenovo"; d.Device = "TB322FC"; d.Model = "TB322FC";
    d.Manufacturer = "LENOVO"; d.Board = "sun";
    d.Display = "TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.202_ST_250919";
    d.Fingerprint = "Lenovo/TB322FC_PRC/TB322FC:15/AQ3A.250129.001/ZUXOS_1.1.11.202_250919_PRC:user/release-keys";
    d.Osv = "15"; d.SdkInt = 35; d.BuildDateUtc = 1759081533; d.BuildPropTimeUtc = 1230768000;
    d.AndroidId = "5358b6fd9144e561"; d.CpuCore = 8; d.Dpi = 440;
    d.TotalCapacity = 482911531008; d.AvailableCapacity = 383974924288; d.TotalMemory = 15882305536;
    d.ResolutionReal = "1520x1904"; d.BootTime = 1782337228220 / 1000; d.P46InstallTime = 1779993900164;

    long sampleCur = 1783465346190;
    string builtFp = PddLib.Crypto.FingerprintBuilder.BuildJson(d, sampleCur);

    // 逐字段对照 (currentTime/bootTime 等运行时值可能不同, 只报差异)
    Console.WriteLine("=== fingerprint 构造 vs 样本 逐字段对照 ===");
    using var s = System.Text.Json.JsonDocument.Parse(sampleFp);
    using var bdoc = System.Text.Json.JsonDocument.Parse(builtFp);
    int diff = 0, tot = 0;
    foreach (var p in s.RootElement.EnumerateObject())
    {
        tot++;
        if (!bdoc.RootElement.TryGetProperty(p.Name, out var bv)) { Console.WriteLine($"  [缺] {p.Name}"); diff++; continue; }
        string sv = p.Value.GetRawText(), cv = bv.GetRawText();
        if (sv != cv) { Console.WriteLine($"  [异] {p.Name}: 样本={Trunc(sv)} 构造={Trunc(cv)}"); diff++; }
    }
    Console.WriteLine($"\n共 {tot} 字段, 差异 {diff} (currentTime/bootTime 等运行时值差异属正常)");

    // FingerprintCodec 往返 (固定 random 0102..20 → 固定 key)
    byte[] fixedRnd = new byte[32]; for (int i = 0; i < 32; i++) fixedRnd[i] = (byte)(i + 1);
    string field = PddLib.Crypto.FingerprintCodec.Encrypt(builtFp, fixedRnd);
    string back = PddLib.Crypto.FingerprintCodec.Decrypt(field, fixedKey);
    Console.WriteLine($"\n[Codec 往返] Encrypt→Decrypt 明文一致: {(back == builtFp ? "PASS" : "FAIL")}");

    static string Trunc(string s) => s.Length > 50 ? s[..50] + "…" : s;
}

// ============================================================
// 从 DeviceProfile 构造 info2 TLV, 与样本逐字段对照 (idx21/22 随机, 跳过值比对)。
// ============================================================
static void AfBuildTest()
{
    const string path = @"f:\TraceWorkspaces\拼多多全量分析\examples\login_send_code_example.txt";
    var m = Regex.Match(File.ReadAllText(path), @"^anti-token:\s*(\S+)\s*$", RegexOptions.Multiline);
    byte[] sampleTlv = PddLib.Crypto.Info2Codec.Decrypt(m.Groups[1].Value);
    var sample = PddLib.Crypto.Info2Tlv.Parse(sampleTlv);

    // 造一台与样本机型一致的设备 (显式设 info2 相关字段)
    var d = PddLib.Register.DeviceProfile.FromSample01();
    d.Sno = "HA2D7KFD";
    d.Brand = "Lenovo"; d.Device = "TB322FC"; d.Model = "TB322FC";
    d.Manufacturer = "LENOVO"; d.Board = "sun";
    d.Display = "TB322FC_CN_OPEN_USER_Q00041.1_V_ZUXOS_1.1.11.202_ST_250919";
    d.BuildId = "AQ3A.250129.001";   // idx08 = BuildId/Display:user/release-keys
    d.Osv = "15"; d.SdkInt = 35;
    d.BuildDateUtc = 1759081533; d.BuildPropTimeUtc = 1230768000;
    d.AndroidId = "5358b6fd9144e561";
    // 电话/网络: 无 SIM 空 + NetworkType=UNKNOWN (默认已如此)

    long sampleCurMs = 1783456280704;
    byte[] builtTlv = PddLib.Crypto.Info2Builder.BuildTlv(d, sampleCurMs);
    var built = PddLib.Crypto.Info2Tlv.Parse(builtTlv);

    Console.WriteLine("=== info2 TLV 构造 vs 样本 逐字段对照 ===");
    Console.WriteLine($"样本 {sample.Entries.Count} 条 / 构造 {built.Entries.Count} 条\n");

    var skip = new HashSet<int> { 0x21, 0x22 };   // 纯随机字段
    int diff = 0;
    foreach (var se in sample.Entries)
    {
        var be = built.Entries.Find(e => e.Index == se.Index);
        if (be == null) { Console.WriteLine($"  idx {se.Index:x2}: 构造缺失"); diff++; continue; }
        bool same = be.Value.AsSpan().SequenceEqual(se.Value);
        if (skip.Contains(se.Index))
        {
            Console.WriteLine($"  idx {se.Index:x2}: [随机, 跳过值] 长度 {(be.Value.Length == se.Value.Length ? "一致" : "不一致")}");
            continue;
        }
        if (!same)
        {
            diff++;
            Console.WriteLine($"  idx {se.Index:x2}: 不一致");
            Console.WriteLine($"      样本 {Convert.ToHexString(se.Value)}");
            Console.WriteLine($"      构造 {Convert.ToHexString(be.Value)}");
        }
    }
    Console.WriteLine(diff == 0
        ? "\n非随机字段全部逐字节一致 PASS"
        : $"\n有 {diff} 处差异 (见上)");

    string anti = PddLib.Crypto.Info2Builder.BuildAntiToken(d, sampleCurMs);
    Console.WriteLine($"\n构造 anti-token: {anti[..40]}... (长度 {anti.Length})");
}

// ============================================================
// 第一次尝试登录: 注册一台设备 → 用其 pddid/会话请求短信验证码, 观察服务端反馈
//   用法: SendTest.exe login <手机号> [proxyUrl]
//   ⚠ 会向该手机号请求真实短信验证码; fingerprint 未实现, 预期服务端可能拒绝。
// ============================================================
static async Task TestLogin(string[] args)
{
    if (args.Length < 2)
    {
        Console.WriteLine("用法: SendTest.exe login <手机号> [proxyUrl]");
        return;
    }
    string mobile = args[1];
    string? proxy = args.Length > 2 ? args[2] : null;

    Console.WriteLine($"=== 完整登录 (注册设备 → 发码 → 控制台输入验证码 → 提交){(proxy != null ? $"  proxy={proxy}" : "")} ===\n");
    try
    {
        // 注册验证码委托: 控制台输入 (不同场景可换成接码平台/短信监听)
        PddLib.SmsCodeHandler codeProvider = ctx =>
        {
            Console.Write($"\n[请输入 {ctx.Mobile} 收到的验证码, 回车提交]: ");
            return Task.FromResult(Console.ReadLine()?.Trim() ?? "");
        };

        var android = await PddLib.Android.CreateNewAsync(proxy, smsCodeProvider: codeProvider);
        Console.WriteLine($"[设备就绪] pddid={android.Pddid}  机型={android.Device.Brand}/{android.Device.Model}");
        Console.WriteLine($"           api_uid={(string.IsNullOrEmpty(android.Device.HeaderApiUid) ? "(无)" : android.Device.HeaderApiUid)}\n");

        Console.WriteLine($"[登录] mobile={mobile}");
        var res = await android.Login(mobile);
        Console.WriteLine($"\n---- 登录结果 ----");
        Console.WriteLine($"  success={res.Success}  stage={res.Stage}  msg={res.Message}");
        if (res.SendCodeResponse != null)
            Console.WriteLine($"  发码响应 HTTP {(int)res.SendCodeResponse.StatusCode}: {res.SendCodeResponse.Body}");
        if (res.LoginResponse != null)
            Console.WriteLine($"  登录响应 HTTP {(int)res.LoginResponse.StatusCode}: {res.LoginResponse.Body}");
        if (res.Success && res.Session != null)
            Console.WriteLine($"  access_token={res.Session.AccessToken}  uid={res.Session.Uid}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[失败] {ex.GetType().Name}: {ex.Message}\n{ex.StackTrace}");
    }
}

// ============================================================
// 完整注册时序: 单台 mock 设备 01→02→03→05, 复用 01 下发的 pddid
// ============================================================
static async Task RunSequence(string? proxy)
{
    Console.WriteLine($"=== 单台 mock 设备完整时序 01→02→03→05{(proxy != null ? $"  (proxy={proxy})" : "")} ===\n");

    var dev = DeviceMocker.NewDevice();
    var client = new RegisterClient(dev, proxy);

    Console.WriteLine("---- mock 设备 ----");
    Console.WriteLine($"  android_id = {dev.AndroidId}");
    Console.WriteLine($"  uuid       = {dev.Uuid}");
    Console.WriteLine($"  oaid       = {dev.Oaid}");
    Console.WriteLine($"  p47        = {dev.P47}\n");

    // ---- 01: 取 pddid ----
    string pddid;
    try
    {
        var r01 = await client.Send01Async();
        pddid = Match(r01.Body, "\"pdd_id\":\"([^\"]+)\"");
        DumpStep("01 /project/meta_info", r01, extra: $"pdd_id={pddid}");
        if (string.IsNullOrEmpty(pddid))
        {
            Console.WriteLine("\n⚠ 01 未取得 pdd_id, 后续步骤无法进行, 终止。");
            return;
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"01 异常: {ex.GetType().Name}: {ex.Message}");
        return;
    }

    // ---- 02: extra data_type=1 ----
    await SendStep("02 extra(data_type=1)", () => client.Send02Async(pddid));
    // ---- 03: extra data_type=20 (双层) ----
    await SendStep("03 extra(data_type=20)", () => client.Send03Async(pddid));
    // ---- 04: meta_info meta_type=all scene=1 (集大成者) ----
    await SendStep("04 meta_info(all,scene=1)", () => client.Send04Async(pddid));
    // ---- 05: extra data_type=17 (wtp) ----
    await SendStep("05 extra(data_type=17)", () => client.Send05Async(pddid));
    // ---- 06: meta_info meta_type=all scene=14 (常规上报, 长 user_env2) ----
    await SendStep("06 meta_info(all,scene=14)", () => client.Send06Async(pddid));

    Console.WriteLine("\n=== 时序完成 ===");
    Console.WriteLine($"pddid = {pddid}");
}

static async Task SendStep(string label, Func<Task<RegisterResponse>> send)
{
    try
    {
        var r = await send();
        DumpStep(label, r);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"\n{label}: 异常 {ex.GetType().Name}: {ex.Message}");
    }
}

static void DumpStep(string label, RegisterResponse r, string? extra = null)
{
    Console.WriteLine($"\n---- {label} ----");
    Console.WriteLine($"  HTTP {(int)r.StatusCode}  etag(resp)={r.Etag ?? "(无)"}");
    if (extra != null) Console.WriteLine($"  {extra}");
    string body = r.Body ?? "";
    string bodyShort = body.Length > 300 ? body[..300] + "…" : body;
    Console.WriteLine($"  body({body.Length}): {bodyShort}");
}

static string Match(string s, string pattern)
{
    var m = Regex.Match(s, pattern);
    return m.Success ? m.Groups[1].Value : "";
}

static int IndexOfBytes(byte[] hay, byte[] needle)
{
    for (int i = 0; i <= hay.Length - needle.Length; i++)
    {
        bool ok = true;
        for (int j = 0; j < needle.Length; j++) if (hay[i + j] != needle[j]) { ok = false; break; }
        if (ok) return i;
    }
    return -1;
}

// ============================================================
// 设备库网关: 调 GetRandomDeviceRecord, 打印随机设备的各事件数据
// ============================================================
static async Task TestGetRandomDevice(string[] args)
{
    if (args.Length < 4)
    {
        Console.WriteLine("用法: SendTest.exe dev <baseUrl> <apiKey> <apiSecret> [ms|sec]");
        return;
    }
    string baseUrl = args[1], apiKey = args[2], apiSecret = args[3];
    var tsUnit = (args.Length > 4 && args[4].Equals("sec", StringComparison.OrdinalIgnoreCase))
        ? PddLib.ClientApi.TsUnit.Seconds : PddLib.ClientApi.TsUnit.Milliseconds;

    var api = new PddLib.ClientApi(baseUrl, apiKey, apiSecret, tsUnit: tsUnit);
    Console.WriteLine($"=== GetRandomDeviceRecord ({baseUrl}, ts={tsUnit}) ===\n");
    string raw = await api.CallRawAsync("GetRandomDeviceRecord");
    Console.WriteLine($"[raw 响应] {(raw.Length > 600 ? raw[..600] + "…" : raw)}\n");
    try
    {
        var rec = await api.GetRandomDeviceRecordAsync();
        if (rec.IsEmpty) { Console.WriteLine("库里没有同时含 1000/1011 的设备 (空列表)。"); return; }
        Console.WriteLine($"x_utdid = {rec.XUtdid}   事件数 = {rec.Events.Count}");
        foreach (var e in rec.Events)
        {
            string d = e.Data ?? "";
            Console.WriteLine($"\n---- event {e.EventName}  (data {d.Length}B) ----");
            Console.WriteLine(d.Length > 400 ? d[..400] + "…" : d);
        }

        // 尝试用 RepedCrypto 解 1011 event 的 body
        string? data1011 = rec.Event1011;
        if (data1011 != null)
        {
            Console.WriteLine("\n==== 解密 1011 event body (RepedCrypto.Decode) ====");
            string body = "";
            try
            {
                using var doc = System.Text.Json.JsonDocument.Parse(data1011);
                if (doc.RootElement.TryGetProperty("body", out var b)) body = b.GetString() ?? "";
            }
            catch { body = data1011; }  // 若 data 本身就是 body
            Console.WriteLine($"body 长度 = {body.Length}");
            try
            {
                var (decRaw, items) = PddLib.Crypto.Taobao.RepedCrypto.Decode(body);
                Console.WriteLine($"[解密成功] 检测项数 = {items?.Count ?? 0}\n");
                if (items != null)
                {
                    foreach (var it in items)
                    {
                        string val = it.BinaryValue != null
                            ? "0x" + Convert.ToHexString(it.BinaryValue)
                            : (it.Value ?? "");
                        if (val.Length > 160) val = val[..160] + "…";
                        Console.WriteLine($"  detect={it.DetectId} policy={it.PolicyId} enc={it.SecondaryEnc} : {val}");
                    }
                    // 落盘完整项 (detect:policy → value), 供离线映射分析
                    var dump = items.ConvertAll(it => new
                    {
                        detect = it.DetectId,
                        policy = it.PolicyId,
                        enc = it.SecondaryEnc.ToString(),
                        value = it.Value,
                        bin = it.BinaryValue != null ? Convert.ToHexString(it.BinaryValue) : null
                    });
                    string outFile = System.IO.Path.Combine(AppContext.BaseDirectory, "taobao_device_items.json");
                    System.IO.File.WriteAllText(outFile,
                        System.Text.Json.JsonSerializer.Serialize(new { rec.XUtdid, items = dump },
                            new System.Text.Json.JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }),
                        new System.Text.UTF8Encoding(false));
                    Console.WriteLine($"\n[dump] 完整项已写: {outFile}");
                }
            }
            catch (Exception dex)
            {
                Console.WriteLine($"[解密失败] {dex.GetType().Name}: {dex.Message}");
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine($"异常: {ex.GetType().Name}: {ex.Message}");
    }
}

// ============================================================
// 淘宝设备 → 转 mock → 完整注册时序 01→02→03→04→05→06 (全环节同一台设备)
// ============================================================
static async Task TestDevSeq(string[] args)
{
    if (args.Length < 4) { Console.WriteLine("用法: SendTest.exe devseq <baseUrl> <apiKey> <apiSecret> [proxyUrl]"); return; }
    string? proxy = args.Length > 4 ? args[4] : null;
    var api = new PddLib.ClientApi(args[1], args[2], args[3]);
    Console.WriteLine($"=== 淘宝→PDD mock 完整时序 01→02→03→04→05→06{(proxy != null ? $"  proxy={proxy}" : "")} ===\n");

    // 取淘宝设备 → 转 mock
    var rec0 = await api.GetRandomDeviceRecordAsync();
    string? d1011 = rec0.Event1011;
    if (d1011 == null) { Console.WriteLine("无 1011 event"); return; }
    string tbody = "";
    try { using var doc = System.Text.Json.JsonDocument.Parse(d1011); if (doc.RootElement.TryGetProperty("body", out var b)) tbody = b.GetString() ?? ""; }
    catch { tbody = d1011; }
    var (_, items) = PddLib.Crypto.Taobao.RepedCrypto.Decode(tbody);
    var tao = new PddLib.Register.TaobaoDeviceRecord(items, rec0.XUtdid);
    var mock = PddLib.Register.DeviceMocker.NewDeviceFromTaobao(tao, out _);
    Console.WriteLine($"机型={mock.Brand}/{mock.Model} osv={mock.Osv} build={mock.BuildId} dpi={mock.Dpi} soc={mock.Soc}");
    Console.WriteLine($"resolution={mock.ResolutionReal} p57={mock.ResolutionUsable} characteristics='{mock.Characteristics}' tz={mock.TimeZone}");
    Console.WriteLine($"android_id={mock.AndroidId}\n");

    var client = new PddLib.Register.RegisterClient(mock, proxy);
    string pddid;
    try
    {
        var r01 = await client.Send01Async();
        pddid = Match(r01.Body, "\"pdd_id\":\"([^\"]+)\"");
        DumpStep("01 /project/meta_info (sub)", r01, $"pdd_id={pddid}");
        if (string.IsNullOrEmpty(pddid)) { Console.WriteLine("\n⚠ 01 无 pddid, 终止"); return; }
    }
    catch (Exception ex) { Console.WriteLine($"01 异常: {ex.Message}"); return; }

    await SendStep("02 extra(data_type=1)", () => client.Send02Async(pddid));
    await SendStep("03 extra(data_type=20)", () => client.Send03Async(pddid));
    await SendStep("16 extra(data_type=16,proc-maps)", () => client.Send16Async(pddid));
    await SendStep("04 meta_info(all,scene=1)", () => client.Send04Async(pddid));
    await SendStep("05 extra(data_type=17)", () => client.Send05Async(pddid));
    await SendStep("06 meta_info(all,scene=14)", () => client.Send06Async(pddid));
    await SendStep("07 extra(data_type=15,es动态)", () => client.Send07Async(pddid));
    await SendStep("08 extra(data_type=21)", () => client.Send08Async(pddid));

    Console.WriteLine($"\n=== 时序完成 pddid={pddid} 机型={mock.Brand}/{mock.Model} ===");
}

// ============================================================
// 淘宝设备 → 转 mock → 发 01: 取真机记录 → NewDeviceFromTaobao → Send01 → 报告 pddid
// ============================================================
static async Task TestDev01(string[] args)
{
    if (args.Length < 4) { Console.WriteLine("用法: SendTest.exe dev01 <baseUrl> <apiKey> <apiSecret> [count] [proxyUrl]"); return; }
    string baseUrl = args[1], apiKey = args[2], apiSecret = args[3];
    int count = args.Length > 4 && int.TryParse(args[4], out int c) ? c : 1;
    string? proxy = args.Length > 5 ? args[5] : null;

    var api = new PddLib.ClientApi(baseUrl, apiKey, apiSecret);
    Console.WriteLine($"=== 淘宝设备 → PDD mock → 发 01 (count={count}{(proxy != null ? $", proxy={proxy}" : "")}) ===");
    Console.WriteLine("目标: api.pinduoduo.com /project/meta_info (01, scene=1)\n");

    var pddIds = new List<string>();
    for (int i = 0; i < count; i++)
    {
        Console.WriteLine($"---- #{i} ----");
        try
        {
            // 1) 取一台随机淘宝设备
            var rec0 = await api.GetRandomDeviceRecordAsync();
            string? d1011 = rec0.Event1011;
            if (d1011 == null) { Console.WriteLine("  无 1011 event, 跳过"); continue; }
            string tbody = "";
            try { using var doc = System.Text.Json.JsonDocument.Parse(d1011); if (doc.RootElement.TryGetProperty("body", out var b)) tbody = b.GetString() ?? ""; }
            catch { tbody = d1011; }
            var (_, items) = PddLib.Crypto.Taobao.RepedCrypto.Decode(tbody);

            // 2) 转 mock (保留机型, 随机唯一值)
            var tao = new PddLib.Register.TaobaoDeviceRecord(items, rec0.XUtdid);
            var mock = PddLib.Register.DeviceMocker.NewDeviceFromTaobao(tao, out _);
            Console.WriteLine($"  机型={mock.Brand}/{mock.Model} osv={mock.Osv} build={mock.BuildId}");
            Console.WriteLine($"  android_id={mock.AndroidId} oaid={mock.Oaid}");

            // 3) 发 01
            var client = new PddLib.Register.RegisterClient(mock, proxy);
            var resp = await client.Send01Async();
            string rb = resp.Body;
            string pddId = Match(rb, "\"pdd_id\":\"([^\"]+)\"");
            bool hasExt = rb.Contains("\"ext_data\"");
            Console.WriteLine($"  HTTP {(int)resp.StatusCode}  pdd_id={(pddId.Length > 0 ? pddId : "(无)")}  ext_data={(hasExt ? "有" : "无")}");
            Console.WriteLine($"  body({rb.Length}): {(rb.Length > 220 ? rb[..220] + "…" : rb)}");
            if (pddId.Length > 0) pddIds.Add(pddId);
        }
        catch (Exception ex) { Console.WriteLine($"  异常: {ex.GetType().Name}: {ex.Message}"); }
        Console.WriteLine();
    }

    Console.WriteLine("=== 汇总 ===");
    Console.WriteLine($"成功 pdd_id: {pddIds.Count}/{count}");
    if (pddIds.Count > 0)
    {
        int uniq = new HashSet<string>(pddIds).Count;
        Console.WriteLine($"  互不相同: {uniq}/{pddIds.Count} {(uniq == pddIds.Count ? "PASS" : "⚠有重复")}");
        Console.WriteLine($"  列表: {string.Join(", ", pddIds)}");
    }
}

// ============================================================
// 淘宝设备 → PDD 基准转换: 取随机设备 → 解 1011 → 转换 → 打印基准 + 报告
// ============================================================
static async Task TestConvert(string[] args)
{
    if (args.Length < 4) { Console.WriteLine("用法: SendTest.exe conv <baseUrl> <apiKey> <apiSecret>"); return; }
    var api = new PddLib.ClientApi(args[1], args[2], args[3]);
    Console.WriteLine("=== 淘宝设备 → PDD 基准转换 ===\n");

    var rec0 = await api.GetRandomDeviceRecordAsync();
    if (rec0.IsEmpty) { Console.WriteLine("空设备。"); return; }
    string? data1011 = rec0.Event1011;
    if (data1011 == null) { Console.WriteLine("无 1011 event。"); return; }

    string body = "";
    try { using var doc = System.Text.Json.JsonDocument.Parse(data1011); if (doc.RootElement.TryGetProperty("body", out var b)) body = b.GetString() ?? ""; }
    catch { body = data1011; }

    var (_, items) = PddLib.Crypto.Taobao.RepedCrypto.Decode(body);
    var tao = new PddLib.Register.TaobaoDeviceRecord(items, rec0.XUtdid);
    var (dev, rep) = PddLib.Register.TaobaoToPddConverter.Convert(tao);

    Console.WriteLine($"[转换基准] brand={dev.Brand} model={dev.Model} osv={dev.Osv} build={dev.BuildId}");
    Console.WriteLine($"  android_id={dev.AndroidId}  mac={dev.P22Mac}");
    Console.WriteLine($"  fingerprint={dev.Fingerprint}");
    Console.WriteLine($"  totalCap={dev.TotalCapacity}  totalMem={dev.TotalMemory}  bootTime={dev.BootTime}");
    Console.WriteLine($"  screen={dev.ScreenWidth}x{dev.ScreenHeight} dpr={dev.Dpr}  inputMethod={dev.InputMethod}");
    Console.WriteLine($"  manufacturer={dev.Manufacturer} board={dev.Board} device={dev.Device} soc/platform={dev.BoardPlatform}");
    Console.WriteLine($"  p4={dev.P4}");
    Console.WriteLine($"  battery={dev.BatteryStatus}");

    Console.WriteLine($"\n[报告] {rep.Summary()}\n");
    Console.WriteLine($"-- 映射成功 ({rep.Mapped.Count}) --");
    foreach (var (f, s, v) in rep.Mapped) Console.WriteLine($"  {f}  ←  {s}  = {v}");
    Console.WriteLine($"\n-- 保留基线 ({rep.Defaulted.Count}) --");
    foreach (var (f, why) in rep.Defaulted) Console.WriteLine($"  {f} : {why}");
    Console.WriteLine($"\n-- 缺失待办 ({rep.Missing.Count}) --");
    foreach (var (f, why) in rep.Missing) Console.WriteLine($"  {f} : {why}");

    // 转换 → mock: 保留机型, 随机化唯一值
    var mock = PddLib.Register.DeviceMocker.NewDeviceFromTaobao(tao, out _);
    Console.WriteLine("\n=== convert → mock (同机型全新设备) ===");
    Console.WriteLine($"  [保留机型] brand={mock.Brand} model={mock.Model} osv={mock.Osv} build={mock.BuildId}");
    Console.WriteLine($"             fingerprint={mock.Fingerprint}");
    Console.WriteLine($"             screen={mock.ScreenWidth}x{mock.ScreenHeight} dpr={mock.Dpr} cpuCore={mock.CpuCore}");
    Console.WriteLine($"  [随机唯一] android_id={mock.AndroidId} (基准 {dev.AndroidId})");
    Console.WriteLine($"             oaid={mock.Oaid}");
    Console.WriteLine($"             uuid={mock.Uuid}");
    Console.WriteLine($"             mac={mock.P22Mac}  p47={mock.P47}");
    Console.WriteLine($"             ip_list={(mock.IpList.Length > 90 ? mock.IpList[..90] + "…" : mock.IpList)}");
    bool brandKept = mock.Brand == dev.Brand && mock.Model == dev.Model && mock.Fingerprint == dev.Fingerprint;
    bool uniqChanged = mock.AndroidId != dev.AndroidId;
    Console.WriteLine($"\n  机型保留={(brandKept ? "PASS" : "FAIL")}  唯一值随机={(uniqChanged ? "PASS" : "FAIL")}");

    // p49 inode 浮动验证: 基准 vs mock 逐段对比
    string csvBase = PddLib.Crypto.P49Codec.DecryptToCsv(dev.P49);
    string csvMock = PddLib.Crypto.P49Codec.DecryptToCsv(mock.P49);
    var sb0 = csvBase.Split(','); var sb1 = csvMock.Split(',');
    int nonEmpty = 0, floated = 0, emptyKept = 0, emptyBroke = 0;
    for (int i = 0; i < Math.Min(sb0.Length, sb1.Length); i++)
    {
        if (sb0[i].Length == 0) { if (sb1[i].Length == 0) emptyKept++; else emptyBroke++; continue; }
        nonEmpty++;
        if (sb0[i] != sb1[i]) floated++;
    }
    Console.WriteLine($"\n  [p49 inode 浮动] 段数={sb0.Length} 非空={nonEmpty} 已浮动={floated} 空段保留={emptyKept} 空段破坏={emptyBroke}");

    // p2 attestation 随机化验证: mock vs 基线 verifiedBootKey 应不同, 且结构可解
    string p2base = PddLib.Register.MetaInfoAllBaseline.P2;
    bool p2Changed = mock.P2 != p2base;
    string P2Key(string wire) { try { var der = Convert.FromBase64String(Uri.UnescapeDataString(wire).Replace("\n","")); int i = IndexOfBytes(der, new byte[]{0xbf,0x85,0x40}); return i < 0 ? "(未定位)" : Convert.ToHexString(der, i+8, 8); } catch { return "(解析失败)"; } }
    Console.WriteLine($"  [p2 attestation] 已随机化={(p2Changed ? "PASS" : "FAIL")}  verifiedBootKey(前8B): 基线={P2Key(p2base)} mock={P2Key(mock.P2)}");
    Console.WriteLine($"    基准 p49 CSV(前100): {(csvBase.Length > 100 ? csvBase[..100] : csvBase)}");
    Console.WriteLine($"    mock p49 CSV(前100): {(csvMock.Length > 100 ? csvMock[..100] : csvMock)}");
}

// ============================================================
// 06 结构校验 (离线): mock 生成的 06 plaintext 字段顺序 == 06 样本字段顺序?
//   验证 scene=14 位置、p48 插入位置、字段齐全 (值可不同, 因 mock 设备/会话不同)。
// ============================================================
static void Verify06Structure()
{
    const string reportPath =
        @"f:\TraceWorkspaces\拼多多全量分析\device_report_example\decrypted\06_meta_info_decrypted.txt";
    Console.WriteLine("=== 06 结构校验 (字段顺序 vs 样本) ===\n");
    if (!File.Exists(reportPath)) { Console.WriteLine($"样本不存在: {reportPath}"); return; }

    string txt = File.ReadAllText(reportPath);
    var m = Regex.Match(txt, @"platform_type=1&.*?&pddid=WqfIGg5r", RegexOptions.Singleline);
    if (!m.Success) { Console.WriteLine("未在样本里定位到 06 明文表单。"); return; }
    string sampleForm = m.Value;

    // mock 生成 06 plaintext (scene=14 + p48 + Form06 user_env2)
    var dev = DeviceMocker.NewDevice();
    var client = new RegisterClient(dev);
    long stMs = 1780084174979;
    var opt = client.BuildMock06Options("WqfIGg5r", stMs);
    byte[] pt = MetaInfoAllBuilder.BuildPlaintext(dev, opt);
    string gotForm = System.Text.Encoding.UTF8.GetString(pt);

    string[] KeysOf(string form) => Array.ConvertAll(form.Split('&'),
        tok => { int e = tok.IndexOf('='); return e >= 0 ? tok[..e] : "(bare:" + tok + ")"; });

    var sk = KeysOf(sampleForm);
    var gk = KeysOf(gotForm);

    Console.WriteLine($"样本 token 数={sk.Length}  mock token 数={gk.Length}");
    int n = Math.Max(sk.Length, gk.Length);
    int mismatches = 0;
    for (int i = 0; i < n; i++)
    {
        string a = i < sk.Length ? sk[i] : "(缺)";
        string b = i < gk.Length ? gk[i] : "(缺)";
        if (a != b)
        {
            mismatches++;
            Console.WriteLine($"  [#{i}] 样本={a}  mock={b}   ← 不一致");
        }
    }
    Console.WriteLine(mismatches == 0
        ? "\n字段顺序完全一致 PASS (scene/p48 位置、字段齐全)"
        : $"\n✗ 有 {mismatches} 处字段顺序不一致");

    // 抽查关键字段值
    string GetVal(string form, string key)
    {
        var mm = Regex.Match(form, "(?:^|&)" + Regex.Escape(key) + "=([^&]*)");
        return mm.Success ? mm.Groups[1].Value : "(无)";
    }
    Console.WriteLine("\n关键字段抽查 (mock):");
    Console.WriteLine($"  scene = {GetVal(gotForm, "scene")}  (样本 {GetVal(sampleForm, "scene")})");
    Console.WriteLine($"  meta_type = {GetVal(gotForm, "meta_type")}");
    Console.WriteLine($"  p48 = {GetVal(gotForm, "p48")}");
    Console.WriteLine($"  known_device = {GetVal(gotForm, "known_device")}");
    Console.WriteLine($"  user_env2 长度 = {GetVal(gotForm, "user_env2").Length} (样本 {GetVal(sampleForm, "user_env2").Length})");
}
