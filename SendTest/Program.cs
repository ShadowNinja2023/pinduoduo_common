using System.Text;
using System.Text.RegularExpressions;
using PddLib.Register;

// ============================================================
// mock 设备端到端发送测试 (向 PDD 生产服务器发 01 报文)
//
//   用法: dotnet run --project SendTest [count] [proxyUrl]
//     count    : 发送的 mock 设备台数 (默认 1)
//     proxyUrl : 可选, 挂抓包代理 (如 http://127.0.0.1:8888)
//
//   验证目标 (NEXT_SESSION 步骤 3/4):
//     - mock 设备发 01 → 服务端是否下发"新" pdd_id (而非样本的 WqfIGg5r)
//     - 多台 mock → 每台 pdd_id 是否互不相同
//
//   安全: 仅用于授权的逆向研究与自有设备注册联调。
// ============================================================

Console.OutputEncoding = Encoding.UTF8;

int count = args.Length > 0 && int.TryParse(args[0], out int c) ? c : 1;
string? proxy = args.Length > 1 ? args[1] : null;

Console.WriteLine($"=== mock 设备端到端发送 (count={count}{(proxy != null ? $", proxy={proxy}" : "")}) ===");
Console.WriteLine("目标: api.pinduoduo.com /project/meta_info  (01 报文, scene=1)\n");

var pddIds = new List<string>();
var sample = DeviceProfile.FromSample01();

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

static string Match(string s, string pattern)
{
    var m = Regex.Match(s, pattern);
    return m.Success ? m.Groups[1].Value : "";
}
