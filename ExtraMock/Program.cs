using System.Text;
using PddLib.Crypto;
using PddLib.Crypto.Extra;

// ============================================================================
// extra(1008) 端到端 mock 演示 —— 用 Unicorn 执行真实 G 生成 keystream。
//
// 证明: 脱离 unidbg, 纯 C# 对【任意 nonce/KEY】完成 extra 容器的 加密(mock) / 解密。
//
// 运行要求 (本项目已配好): <CETCompat>false</CETCompat> + post-build 清 apphost GUARD_CF;
// unicorn.dll 由 PddLib 的 Uc DllImport 解析器从 Native/ 或 Data/Extra1008/ 定位。
// ============================================================================

Console.OutputEncoding = Encoding.UTF8;

// ── 模式: 解出某报文里 user_env2 内嵌 extra 的明文 ──
//   用法: ExtraMock.exe ue2 <解密报文.txt 路径>
if (args.Length > 0 && args[0].Equals("ue2", StringComparison.OrdinalIgnoreCase))
{
    string rp = args.Length > 1 && !args[1].StartsWith("--") ? args[1]
        : @"f:\TraceWorkspaces\拼多多全量分析\device_report_example\decrypted\06_meta_info_decrypted.txt";
    int gi = Array.FindIndex(args, a => a.Equals("--gen", StringComparison.OrdinalIgnoreCase));
    string? genPath = gi >= 0 && gi + 1 < args.Length ? args[gi + 1] : null;
    return DecryptUe2Extra(rp, genPath);
}

int pass = 0, fail = 0;
void Check(string name, bool ok, string? detail = null)
{
    Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail != null ? "  " + detail : "")}");
    if (ok) pass++; else fail++;
}

// 真机 _b 容器 (105B)
byte[] bContainer = Extra1008Codec.HexToBytes(
    "0fc100001008002b004d4279f1e04296" + "1000231fc38e6fc7700e6a702bf19b19" +
    "bf4c22d0e64d5a50130787d32e1e157b" + "eeb8df891e000501daa4c8c67cb0f2c9" +
    "3d7e3a7ba635fb3128079188e93b32a2" + "0b2a64b71527d000050d28852652bb81" +
    "3f2be3da2ca517dd35");
const string bPlain = "{\"rand\":\"D8EAAAQEAAXFxcRa28XB6VY=\",\"userenv\":{\"4\":{\"2\":[\"\"],\"3\":[\"\"]},\"seq\":4}}";

var keyTable = KeyTable.LoadDefault();

try
{
    using var g = new UnicornKeystreamGenerator();   // 真实 G (Unicorn 执行 libdyncommon)
    var codec = new Extra1008Codec(keyTable, g);

    Console.WriteLine("=== extra(1008) 真实 G (Unicorn) 端到端 ===\n");

    // 1) 解真机 _b 容器 (确定性 lenflag 解码)
    var r = codec.DecryptByLenflag(bContainer);
    Check("[1] 解真机 _b == 期望明文", r.PlaintextUtf8 == bPlain);
    Console.WriteLine($"    KEY_8B={Seed.ToHex(r.Key8)}  nonce={Convert.ToHexString(r.Nonce).ToLowerInvariant()}");
    Console.WriteLine($"    明文: {r.PlaintextUtf8}");

    // 2) 逐字节往返: 用真实 G 重编码 _b, 应 == 原始容器
    var w0 = Index3.FromMarker(bContainer.AsSpan(53, 4));
    var w1 = Index3.FromMarker(bContainer.AsSpan(87, 4));
    byte[] reenc = codec.Encrypt(Encoding.UTF8.GetBytes(bPlain), r.Nonce, r.Counter, w0, w1, 53, 87);
    Check("[2] 真实 G 重编码 _b 逐字节 == 原始容器",
        Convert.ToHexString(reenc) == Convert.ToHexString(bContainer), $"{reenc.Length}B");

    // 3) ★ 任意 nonce/KEY mock: 全新 nonce + 任选 KEY 索引 + 自定义明文
    byte[] nonce = Extra1008Codec.HexToBytes("aabbccdd");   // 全新 nonce
    byte[] counter = Extra1008Codec.HexToBytes("1000");
    var mw0 = new Index3(1, 2, 3);                          // 任选合法索引 (查 KeyTable 得 KEY_8B)
    var mw1 = new Index3(4, 5, 6);
    byte[] pt = Encoding.UTF8.GetBytes("{\"mock\":\"pdd_extra\",\"userenv\":{\"seq\":1}}");
    byte[] mock = codec.EncryptMock(pt, nonce, counter, mw0, mw1);
    var back = codec.DecryptByLenflag(mock);
    Check("[3] 任意 nonce/KEY mock 往返明文一致", back.PlaintextUtf8 == Encoding.UTF8.GetString(pt));
    Console.WriteLine($"    mock 容器({mock.Length}B) KEY_8B={Seed.ToHex(back.Key8)} nonce=aabbccdd");
    Console.WriteLine($"    解回: {back.PlaintextUtf8}");

    // 4) 长明文 (>41 块) 验证块预算 patch 生效
    byte[] longPt = Encoding.UTF8.GetBytes("{\"blob\":\"" + new string('A', 900) + "\",\"seq\":9}");
    byte[] longMock = codec.EncryptMock(longPt, nonce, counter, mw0, mw1);
    var longBack = codec.DecryptByLenflag(longMock);
    Check("[4] 长明文(>41块) mock 往返一致", longBack.PlaintextUtf8 == Encoding.UTF8.GetString(longPt),
        $"{longMock.Length}B ({(longMock.Length + 15) / 16}块)");

    // ===== 全链路串联: user_env2 外层(TEA-CBC) ↔ 内层 extra(1008) =====
    Console.WriteLine("\n=== 全链路: user_env2 外层 ↔ extra 内层 (纯 C#) ===");

    // 真机 _b 的 user_env2 外层 blob (TEA-CBC base64)
    const string bUserEnv2Blob =
        "fKngCeNhzVcydUeyFLBk3BSFNjN9bh8bZD8C7S3+qMnx7v6FO2j6A9lcynweaBmuwmA6fCf5awNY38EiD3714Dn+s+4YwrEELu9LEnMrAU2HKHhj6EuM52js1ef0bn1KNjChvENI/NnpMBNRpA9YdY6e+mBLmHR2B1mD5db3mr65UZDqn35xx/iSAWzKtztCoMaKCaGK3O8QMALbboxFw5uaa81yBAv5lH/5iZl97WlmMF2ydlkCSofbyhGJhhHXAl2tAtSgHMAF0BcDG0r5oMCactbR/JjxLM2M9gbisuatCcQfPBMFRnkmoskA1MU1qPjW2uMVDBdKxnMsBpB44JuHq+DjqbuqbTbDMG1yovw6Y+MzxHhJkVWf7zGgpXrF3TcAB9yAn7pmisxhIloLEPOEkVMiS/ne6JxFnL+q73c7f7TKNT+YE9PMt5LdVBuEUYtAxfh4kvAU4F17Mk6XJSIiQ3R7rot7fatYZh+Ncxo=";

    // 5) 外层解出内层容器, 应 == 已知 _b 容器 (105B)
    byte[] extractedContainer = ExtraPipeline.ExtractContainer(bUserEnv2Blob);
    Check("[5] 外层 TEA-CBC 解出内层 extra 容器 == _b 容器",
        Convert.ToHexString(extractedContainer) == Convert.ToHexString(bContainer),
        $"{extractedContainer.Length}B");

    // 6) 全链路解密: user_env2 blob → 容器 → 明文 JSON
    var e2e = codec.DecryptByLenflag(extractedContainer);
    Check("[6] 全链路 (外层→内层→明文) == 期望", e2e.PlaintextUtf8 == bPlain);

    // 7) ★ mock 全链路: 自造 extra → 塞进 user_env2(Form06) → TEA-CBC → 再解回
    byte[] mockContainer = codec.EncryptMock(pt, nonce, counter, mw0, mw1);
    string extraField = ExtraPipeline.ToExtraField(mockContainer);   // "01"+base64
    string ue2Blob = UserEnv2Codec.GenerateFrom(
        UserEnv2Codec.Form06("5358b6fd9144e561", 1780084174940, 11, "0||1904x1520|16515|1", extraField));
    // 解回: 外层 → extra 字段 → 容器 → 明文
    byte[] backContainer = ExtraPipeline.ExtractContainer(ue2Blob);
    var mockBack = codec.DecryptByLenflag(backContainer);
    Check("[7] mock 全链路 (extra→user_env2→TEA-CBC→解回) 明文一致",
        mockBack.PlaintextUtf8 == Encoding.UTF8.GetString(pt), $"user_env2 {ue2Blob.Length} chars");
}
catch (DllNotFoundException)
{
    Console.WriteLine("[跳过] 未找到 unicorn.dll (应在输出目录 或 Native/ 或 Data/Extra1008/)。");
}
catch (Exception e)
{
    Console.WriteLine($"[错误] {e.GetType().Name}: {e.Message}");
    fail++;
}

Console.WriteLine($"\n==== 汇总: PASS={pass}  FAIL={fail} ====");
return fail == 0 ? 0 : 1;


// ============================================================================
// 从解密报文里提取 user_env2 → URL 解码 → 外层 TEA-CBC 取内层 extra 容器 →
// 真实 G (Unicorn) 解出 extra 明文, 打印字段值。
// ============================================================================
static int DecryptUe2Extra(string reportPath, string? genPath = null)
{
    Console.WriteLine($"=== 解 user_env2 内嵌 extra ({System.IO.Path.GetFileName(reportPath)}) ===\n");
    if (!System.IO.File.Exists(reportPath))
    {
        Console.WriteLine($"[错误] 报文文件不存在: {reportPath}");
        return 1;
    }

    string text = System.IO.File.ReadAllText(reportPath);
    var m = System.Text.RegularExpressions.Regex.Match(text, @"user_env2=([^&]+)");
    if (!m.Success)
    {
        Console.WriteLine("[错误] 未在报文里找到 user_env2 字段。");
        return 1;
    }

    // Java URLEncoder 逆: 该 base64 blob 内无字面空格, 所有 +/=/ 都是 %XX 编码 → UnescapeDataString 正确。
    string ue2Blob = Uri.UnescapeDataString(m.Groups[1].Value);
    Console.WriteLine($"user_env2 blob: {ue2Blob.Length} chars");

    try
    {
        // 1) 先看外层 user_env2 明文 JSON (含 4/8/an/id/ts/seq/pk/ver/extra)
        string ue2Plain = UserEnv2Codec.Decrypt(ue2Blob);
        Console.WriteLine($"\n--- 外层 user_env2 明文 JSON ({ue2Plain.Length}B) ---");
        Console.WriteLine(ue2Plain);

        // 可选: 生成 06 user_env2 基线常量文件 (extra 字段 + realtime + pk), 供 RegisterClient 复刻
        if (genPath != null)
        {
            GenUe2Form06Baseline(ue2Plain, genPath);
            Console.WriteLine($"[gen] 已写基线常量: {genPath}");
        }

        // 2) 取内层 extra 容器 (去 "01" + base64 → 容器字节)
        byte[] container = ExtraPipeline.ExtractContainer(ue2Blob);
        Console.WriteLine($"\n--- 内层 extra 容器 ---");
        Console.WriteLine($"容器长度: {container.Length}B  头16B: {Convert.ToHexString(container.AsSpan(0, Math.Min(16, container.Length))).ToLowerInvariant()}");

        // 3) 真实 G 解密容器 → extra 明文
        var keyTable = KeyTable.LoadDefault();
        using var g = new UnicornKeystreamGenerator();
        var codec = new Extra1008Codec(keyTable, g);
        var r = codec.DecryptByLenflag(container);

        Console.WriteLine($"\n--- extra 解密 ---");
        Console.WriteLine($"nonce={Convert.ToHexString(r.Nonce).ToLowerInvariant()}  counter={Convert.ToHexString(r.Counter).ToLowerInvariant()}  KEY_8B={Seed.ToHex(r.Key8)}");
        Console.WriteLine($"明文长度: {r.Plaintext.Length}B");
        double printable = 0;
        foreach (byte b in r.Plaintext) if (b >= 0x20 && b < 0x7f) printable++;
        Console.WriteLine($"可打印率: {printable / r.Plaintext.Length:F3}");
        Console.WriteLine($"\n--- extra 明文字段值 ---\n{r.PlaintextUtf8}");
        return 0;
    }
    catch (DllNotFoundException)
    {
        Console.WriteLine("[跳过] 未找到 unicorn.dll。");
        return 1;
    }
    catch (Exception e)
    {
        Console.WriteLine($"[错误] {e.GetType().Name}: {e.Message}\n{e.StackTrace}");
        return 1;
    }
}

// 从 06 user_env2 明文 JSON 抽取 extra 字段 + "8".realtime 的 content + pk, 生成 C# 基线常量文件。
static void GenUe2Form06Baseline(string ue2Plain, string outPath)
{
    using var doc = System.Text.Json.JsonDocument.Parse(ue2Plain);
    var root = doc.RootElement;
    string extra = root.GetProperty("extra").GetString() ?? "";
    string pk = root.TryGetProperty("pk", out var pkEl) ? (pkEl.GetString() ?? "") : "";
    // "8".realtime 是一个 JSON 字符串: {"content":"0||1904x1520|16515|1"}
    string realtimeContent = "";
    if (root.TryGetProperty("8", out var e8) && e8.TryGetProperty("realtime", out var rt))
    {
        using var rtDoc = System.Text.Json.JsonDocument.Parse(rt.GetString() ?? "{}");
        if (rtDoc.RootElement.TryGetProperty("content", out var c)) realtimeContent = c.GetString() ?? "";
    }

    var sb = new StringBuilder();
    sb.AppendLine("// 自动生成 (ExtraMock ue2 --gen)。06 报文 user_env2 (Form06 长形态) 基线常量。");
    sb.AppendLine("// 来源: device_report_example 06 样本 (Lenovo TB322FC)。extra 无 per-台唯一 ID, 复刻安全。");
    sb.AppendLine("namespace PddLib.Register");
    sb.AppendLine("{");
    sb.AppendLine("    /// <summary>06 user_env2 (Form06) 基线: realtime 分辨率内容 / pk 句柄 / extra 检测容器 (复刻样本)。</summary>");
    sb.AppendLine("    public static class Ue2Form06Baseline");
    sb.AppendLine("    {");
    sb.AppendLine($"        public const string RealtimeContent = @\"{realtimeContent.Replace("\"", "\"\"")}\";");
    sb.AppendLine($"        public const string Pk = @\"{pk.Replace("\"", "\"\"")}\";");
    sb.AppendLine($"        public const string ExtraField = @\"{extra.Replace("\"", "\"\"")}\";");
    sb.AppendLine("    }");
    sb.AppendLine("}");
    System.IO.File.WriteAllText(outPath, sb.ToString(), new UTF8Encoding(false));
}
