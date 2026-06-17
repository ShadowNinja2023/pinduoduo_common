using System.Text;
using System.Text.Json;
using PddLib.Crypto;
using PddLib.Register;

// ============================================================
// Phase A 验证: 用固定 key 复刻 01 报文 data 字段, 逐字节比对样本
// ============================================================

// 样本 01 报文 data 字段 (从 device_report_example/01_meta_info.txt 提取)
string sampleFile = args.Length > 0
    ? args[0]
    : @"f:\TraceWorkspaces\拼多多全量分析\device_report_example\01_meta_info.txt";

Console.OutputEncoding = Encoding.UTF8;
Console.WriteLine("=== Phase A: 01 报文 body 离线复刻验证 ===\n");

string content = File.ReadAllText(sampleFile, Encoding.UTF8);
int idx = content.LastIndexOf("{\"key\"", StringComparison.Ordinal);
string bodyJson = content[idx..].Trim();
using var doc = JsonDocument.Parse(bodyJson);
string sampleData = doc.RootElement.GetProperty("data").GetString()!;

// 固定 key = random32[:16]
byte[] fixedKey16 = PddBodyCrypto.FixedRandom32[..16];

// 1) 解出样本 plaintext (基准)
byte[] samplePt = PddBodyCrypto.AesCbcDecrypt(Convert.FromBase64String(sampleData), fixedKey16);
string samplePtStr = Encoding.UTF8.GetString(samplePt);

// 2) 用 Builder 复刻 plaintext
var device = DeviceProfile.FromSample01();
byte[] builtPt = MetaInfoSubBuilder.BuildPlaintext(device, pddid: "");
string builtPtStr = Encoding.UTF8.GetString(builtPt);

// 3) plaintext 比对
bool ptMatch = samplePtStr == builtPtStr;
Console.WriteLine($"样本 plaintext 长度: {samplePt.Length}");
Console.WriteLine($"复刻 plaintext 长度: {builtPt.Length}");
Console.WriteLine($"[plaintext 逐字节一致] {(ptMatch ? "PASS" : "FAIL")}");

if (!ptMatch)
{
    int min = Math.Min(samplePtStr.Length, builtPtStr.Length);
    int diff = -1;
    for (int i = 0; i < min; i++)
        if (samplePtStr[i] != builtPtStr[i]) { diff = i; break; }
    if (diff < 0) diff = min;
    int s = Math.Max(0, diff - 40);
    Console.WriteLine($"\n首个差异 @ {diff}:");
    Console.WriteLine($"  样本: ...{Safe(samplePtStr, s, diff + 40)}");
    Console.WriteLine($"  复刻: ...{Safe(builtPtStr, s, diff + 40)}");
    // 字段级 diff
    var sa = samplePtStr.Split('&');
    var ba = builtPtStr.Split('&');
    Console.WriteLine($"\n样本 token 数={sa.Length}, 复刻 token 数={ba.Length}");
    int n = Math.Min(sa.Length, ba.Length);
    int shown = 0;
    for (int i = 0; i < n && shown < 20; i++)
        if (sa[i] != ba[i])
        {
            Console.WriteLine($"  token[{i}] 样本='{Trunc(sa[i])}'  复刻='{Trunc(ba[i])}'");
            shown++;
        }
}

// 4) AES 重新加密比对 (即使 plaintext 一致也确认 AES 链)
string builtData = PddBodyCrypto.EncryptData(builtPt, fixedKey16);
Console.WriteLine($"\n[AES(data) 逐字节一致] {(builtData == sampleData ? "PASS" : "FAIL")}");

// 5) RSA 公钥自检: 加密 random32 -> 输出 128 字节 (上线路径冒烟)
try
{
    string packet = PddBodyCrypto.EncryptPacket(builtPt, PddBodyCrypto.FixedRandom32);
    string keyB64 = ExtractKey(packet);
    byte[] keyBlob = Convert.FromBase64String(keyB64);
    Console.WriteLine($"[RSA(key) 输出长度] {keyBlob.Length} 字节 (期望 128) {(keyBlob.Length == 128 ? "PASS" : "FAIL")}");
}
catch (Exception ex)
{
    Console.WriteLine($"[RSA(key)] 异常: {ex.Message}");
}

// 6) 完整 01 请求 dry-run (不发送), 打印关键 header
var client = new RegisterClient(device);
var req = client.Build01(st: 1780084169928, random32: PddBodyCrypto.FixedRandom32);
Console.WriteLine("\n=== 01 完整请求 dry-run ===");
Console.WriteLine($"{req.Method} {req.RequestUri}");
foreach (var hh in req.Headers)
{
    string val = string.Join(",", hh.Value);
    if (val.Length > 80) val = val[..80] + "...";
    Console.WriteLine($"  {hh.Key}: {val}");
}

Console.WriteLine("\n=== 完成 ===");

// 7) x-p1 端到端验证: 复现真机 sdr 示例 (bd = body JSON 原文)
Console.WriteLine("\n=== x-p1 端到端验证 (真机 sdr 示例) ===");
{
    string ul = "/project/meta_info";
    string et = "";
    string st = "1780119380946";
    string p47 = "wJtHZtwB-C0Wz-OVhn-627d-0AFZBt7ErTKC";
    string seg3 = "410a";
    string ts2 = "1780119379986";
    // bd = base64 解码后的 body JSON 原文 (从 sdr_call_example.txt 读取完整 bd)
    string exampleFile = @"f:\TraceWorkspaces\拼多多全量分析\examples\sdr_call_example.txt";
    string ex = File.ReadAllText(exampleFile, Encoding.UTF8);
    int mi = ex.IndexOf("\"bd\":\"", StringComparison.Ordinal) + 6;
    int me = ex.IndexOf('"', mi);
    string fullBdB64 = ex[mi..me];
    string bdJson = Encoding.UTF8.GetString(Convert.FromBase64String(fullBdB64));

    string expectXp1 = "MDQwMTAxd0p0SFp0d0ItQzBXei1PVmhuLTYyN2QtMEFGWkJ0N0VyVEtDuChIueXuhoCLXHFYlxV5BOtQC2tmvN7JiUc62cYVdqbUqcLeJhzLB7dchAqxTK3xr7uLoxNxOGIrryhC3Geb6CVMkD1nx4bWkXem3Yod";

    string gotXp1 = XP1Codec.Generate(ul, bdJson, et, st, p47, ac: "", ck: "", seg3: seg3, ts2: ts2);
    Console.WriteLine($"[XP1Codec 复现真机 x-p1] {(gotXp1 == expectXp1 ? "PASS 逐字节一致" : "FAIL")}");
    if (gotXp1 != expectXp1)
    {
        Console.WriteLine($"  期望: {expectXp1}");
        Console.WriteLine($"  实际: {gotXp1}");
    }
}

// 8) 实测发送 01 报文 (真随机 key + 新版 RSA 公钥)
Console.WriteLine("\n=== Phase B: 发送 01 报文 ===");

async Task<string> Send(string label, Func<RegisterClient, Task<RegisterResponse>> action)
{
    var dev = DeviceProfile.FromSample01();
    var cli = new RegisterClient(dev);
    try
    {
        var resp = await action(cli);
        Console.WriteLine($"\n[{label}] HTTP {(int)resp.StatusCode}  etag(resp)={resp.Etag ?? "(无)"}");
        Console.WriteLine($"   body({resp.Body.Length}): {resp.Body}");
        return resp.Body;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"\n[{label}] 异常: {ex.Message}");
        return "";
    }
}

// 真随机 key + 新版 RSA 公钥 → 服务端应解密成功并回显 pdd_id
string body = await Send("真随机key+新版公钥", c => c.Send01Async());
Console.WriteLine("\n=== 结论 ===");
Console.WriteLine($"含非空 pdd_id?   {System.Text.RegularExpressions.Regex.IsMatch(body, "\"pdd_id\":\"[^\"]+\"")}");
Console.WriteLine($"回显 WqfIGg5r?   {body.Contains("WqfIGg5r")}");
Console.WriteLine($"含 ext_data?     {body.Contains("\"ext_data\":{")}");

static string Safe(string s, int a, int b)
{
    a = Math.Max(0, a); b = Math.Min(s.Length, b);
    return s[a..b];
}
static string Trunc(string s) => s.Length > 50 ? s[..50] + "..." : s;

// 取 EncryptPacket 输出中的 key 字段 (base64)
static string ExtractKey(string packet)
{
    const string m = "\"key\":\"";
    int s = packet.IndexOf(m, StringComparison.Ordinal) + m.Length;
    int e = packet.IndexOf('"', s);
    return packet[s..e];
}
