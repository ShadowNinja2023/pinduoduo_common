using System.Text;
using PddLib.Crypto;
using PddLib.Register;

// ============================================================
// DeviceMocker 数据对比工具 (不发网络)
//   1. 样本设备 vs mock 设备 字段级对比 (A/B/C/D 类)
//   2. mock 设备 01 报文 plaintext (108 token, 解密后) 输出
//   3. C 类绑定字段自洽性校验 (user_env2 解回新 android_id / p30 空列表)
//   4. 多台 mock 设备唯一性抽样
// 用于与真机抓包逐字段比对, 确认机型字段不变、唯一性字段已随机化。
// ============================================================

Console.OutputEncoding = Encoding.UTF8;

var sample = DeviceProfile.FromSample01();
var mock = DeviceMocker.NewDevice();

Console.WriteLine("================ 1. 字段级对比 (样本 vs mock) ================\n");

PrintSection("A. 必须随机化 (硬唯一标识) — 应全部 [变]");
Row("android_id", sample.AndroidId, mock.AndroidId);
Row("oaid", sample.Oaid, mock.Oaid);
Row("sharedpreference_id", sample.SharedPreferenceId, mock.SharedPreferenceId);
Row("uuid", sample.Uuid, mock.Uuid);
Row("p22 (MAC)", sample.P22Mac, mock.P22Mac);
Row("p47", sample.P47, mock.P47);

PrintSection("\nB. 关联派生 (建议随机化) — 应 [变] / 凭据置空");
Row("p46 (install_ms)", sample.P46InstallTime.ToString(), mock.P46InstallTime.ToString());
Row("p90", sample.P90, mock.P90);
Row("boot_time", sample.BootTime.ToString(), mock.BootTime.ToString());
Row("did_info", sample.DidInfo, mock.DidInfo);
Row("ip_list", sample.IpList, mock.IpList);
Row("p7 (大型app标识)", sample.P7AbnormalApps, mock.P7AbnormalApps);
Row("battery_status", sample.BatteryStatus, mock.BatteryStatus);
Row("totalcapacity", sample.TotalCapacity.ToString(), mock.TotalCapacity.ToString());
Row("availablecapacity", sample.AvailableCapacity.ToString(), mock.AvailableCapacity.ToString());
Row("totalmemory", sample.TotalMemory.ToString(), mock.TotalMemory.ToString());
Row("body cookie", sample.BodyCookie, mock.BodyCookie);
Row("header api_uid", sample.HeaderApiUid, mock.HeaderApiUid);
Row("adb_enabled", sample.AdbEnabled.ToString(), mock.AdbEnabled.ToString());
Row("development_enabled", sample.DevelopmentEnabled.ToString(), mock.DevelopmentEnabled.ToString());

PrintSection("\nC. 设备绑定加密 (用新值重算) — 应 [变]");
Row("user_env2", sample.UserEnv2, mock.UserEnv2);
Row("p30", sample.P30, mock.P30);
Row("p49 (inode指纹)", sample.P49, mock.P49);
Row("p125 (随机UUID)", sample.P125, mock.P125);

PrintSection("\nD. 机型指纹 (保持不变) — 应全部 [同]");
Row("fingerprint", sample.Fingerprint, mock.Fingerprint);
Row("p4 (uname)", sample.P4, mock.P4);
Row("build_id", sample.BuildId, mock.BuildId);
Row("model", sample.Model, mock.Model);
Row("brand", sample.Brand, mock.Brand);
Row("osv", sample.Osv, mock.Osv);
Row("分辨率 W x H", $"{sample.ScreenWidth}x{sample.ScreenHeight}", $"{mock.ScreenWidth}x{mock.ScreenHeight}");

PrintSection("\nD'. 02 环境动态量 (机型不变但每机取值不同) — 应 [变]");
Row("cpuFrequency (curFreq)", sample.CpuFrequencyJson, mock.CpuFrequencyJson);
Row("volume", sample.VolumeJson, mock.VolumeJson);

Console.WriteLine("\n================ 2. C 类绑定字段自洽性校验 ================\n");

// user_env2: 解回的明文应含 mock 的新 android_id (而非样本旧值)
long ts = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
mock.RecomputeUserEnv2(ts);
string uesPlain = DecryptUserEnv2(mock.UserEnv2);
bool uesOk = uesPlain.Contains($"\"id\":\"{mock.AndroidId}\"");
Console.WriteLine($"user_env2 重算明文 : {uesPlain}");
Console.WriteLine($"  含新 android_id  : {(uesOk ? "PASS" : "FAIL")}  (mock android_id={mock.AndroidId})");
Console.WriteLine($"  不含旧样本 id    : {(!uesPlain.Contains("5358b6fd9144e561") ? "PASS" : "FAIL")}");

// p30: 解密应为空 (干净设备无风险应用)
string p30Plain = P30Codec.DecryptBase64(System.Net.WebUtility.UrlDecode(mock.P30));
Console.WriteLine($"\np30 解密明文     : '{p30Plain}'  (空=干净设备)");
Console.WriteLine($"  无 hunter 风险项 : {(!p30Plain.Contains("hunter") && p30Plain.Length == 0 ? "PASS" : "FAIL")}");

// p125: 解密应为合法 UUID 字符串
string p125Uuid = P125Codec.Decrypt(mock.P125);
bool p125Ok = Guid.TryParse(p125Uuid, out _);
Console.WriteLine($"\np125 解密明文    : {p125Uuid}");
Console.WriteLine($"  是合法 UUID     : {(p125Ok ? "PASS" : "FAIL")}");
Console.WriteLine($"  与报文 uuid 不同 : {(p125Uuid != mock.Uuid ? "PASS" : "FAIL")}  (独立 UUID)");

// p49 codec 自检: 样本基线 CSV 解密 → 重加密往返一致
string sampleCsv = P49Codec.DecryptToCsv(sample.P49);
string reEnc = P49Codec.EncryptCsv(sampleCsv);
Console.WriteLine($"\np49 样本 CSV 段数: {sampleCsv.Split(',').Length} (88 个系统文件 inode 字段)");
Console.WriteLine($"  样本 CSV       : {Trunc(sampleCsv)}");
Console.WriteLine($"  解密→重加密往返 : {(reEnc == sample.P49 ? "PASS 逐字节一致" : "FAIL")}");

// p49 mock: 只扰动可变索引, 其余保留; 校验非可变段与样本一致、可变段已变
string mockCsv = P49Codec.DecryptToCsv(mock.P49);
string[] sParts = sampleCsv.Split(','), mParts = mockCsv.Split(',');
var varSet = new HashSet<int>(P49Codec.VariableIndices);
int keptOk = 0, keptTotal = 0, changed = 0;
for (int i = 0; i < Math.Min(sParts.Length, mParts.Length); i++)
{
    if (varSet.Contains(i))
    {
        if (sParts[i].Length > 0 && sParts[i] != mParts[i]) changed++;
    }
    else
    {
        keptTotal++;
        if (sParts[i] == mParts[i]) keptOk++;
    }
}
Console.WriteLine($"  非可变段保留   : {keptOk}/{keptTotal} {(keptOk == keptTotal ? "PASS" : "FAIL")}");
Console.WriteLine($"  可变段已扰动   : {changed} 个 (示例: proc/self 样本={GetIdx(sParts,85)} mock={GetIdx(mParts,85)})");

Console.WriteLine("\n================ 3. mock 设备 01 报文 plaintext (解密后 108 token) ================\n");

byte[] pt = MetaInfoSubBuilder.BuildPlaintext(mock, pddid: "");
string ptStr = Encoding.UTF8.GetString(pt);
var tokens = ptStr.Split('&');
Console.WriteLine($"token 数: {tokens.Length}\n");
for (int i = 0; i < tokens.Length; i++)
    Console.WriteLine($"  [{i,3}] {tokens[i]}");

// 同时落盘, 方便逐字段 diff
string outDir = AppContext.BaseDirectory;
string outFile = System.IO.Path.Combine(outDir, "mock_01_plaintext.txt");
System.IO.File.WriteAllText(outFile, ptStr, new UTF8Encoding(false));
Console.WriteLine($"\nplaintext 已写出: {outFile}");

Console.WriteLine("\n================ 4. 多台 mock 设备唯一性抽样 (5 台) ================\n");
Console.WriteLine($"{"#",-3} {"android_id",-18} {"oaid",-34} {"p47",-38}");
var ids = new HashSet<string>();
for (int i = 0; i < 5; i++)
{
    var dv = DeviceMocker.NewDevice();
    ids.Add(dv.AndroidId);
    Console.WriteLine($"{i,-3} {dv.AndroidId,-18} {dv.Oaid,-34} {dv.P47,-38}");
}
Console.WriteLine($"\nandroid_id 全唯一: {(ids.Count == 5 ? "PASS" : "FAIL")}");

Console.WriteLine("\n================ 5. 输出两台 mock 设备到文件 (并排 diff) ================\n");

string projDir = System.IO.Path.GetFullPath(
    System.IO.Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
string outDir2 = System.IO.Path.Combine(projDir, "out");
System.IO.Directory.CreateDirectory(outDir2);

void DumpDevice(string fileName, DeviceProfile dev)
{
    long ts2 = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    dev.RecomputeUserEnv2(ts2);
    byte[] p = MetaInfoSubBuilder.BuildPlaintext(dev, pddid: "");
    var toks = Encoding.UTF8.GetString(p).Split('&');

    var tokens = new List<object>(toks.Length);
    for (int i = 0; i < toks.Length; i++)
    {
        int eq = toks[i].IndexOf('=');
        if (eq >= 0)
            tokens.Add(new { i, k = toks[i][..eq], v = toks[i][(eq + 1)..] });
        else
            tokens.Add(new { i, k = (string?)null, v = toks[i] }); // 裸占位 (null/空段)
    }

    var obj = new
    {
        android_id = dev.AndroidId,
        uuid = dev.Uuid,
        oaid = dev.Oaid,
        p47 = dev.P47,
        tokenCount = toks.Length,
        tokens
    };

    var jsonOpts = new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    string json = System.Text.Json.JsonSerializer.Serialize(obj, jsonOpts);
    string path = System.IO.Path.Combine(outDir2, fileName);
    System.IO.File.WriteAllText(path, json, new UTF8Encoding(false));
    Console.WriteLine($"  已写出: {path}");
}

DumpDevice("mock_device_1.json", DeviceMocker.NewDevice());
DumpDevice("mock_device_2.json", DeviceMocker.NewDevice());
Console.WriteLine("\n  对比建议: 唯一性字段 (A/B/C 类 token) 两文件应不同; 机型字段 (D 类) 应完全相同。");

// ================================================================
// 6. 02 报文 (extra/data_type=1) 验证 + 两台 mock 设备数据落盘
// ================================================================
Console.WriteLine("\n================ 6. 02 报文逐字节复刻验证 (样本设备) ================\n");
{
    // 样本运行时值 (取自 02_extra.txt 解密结果)
    const string samplePddid = "WqfIGg5r";
    const long sampleCurrent = 1780084169437;
    const long sampleActive = 89703557;
    const int sampleProcId = 581;

    var sampleDev = DeviceProfile.FromSample01();  // 机型/字段 = 样本基线
    byte[] pt02 = Extra02Builder.BuildPlaintext(sampleDev, samplePddid, sampleCurrent, sampleActive, sampleProcId);
    string got02 = Encoding.UTF8.GetString(pt02);

    string fixturePath = System.IO.Path.Combine(AppContext.BaseDirectory, "sample_02_plaintext.json");
    string expect02 = System.IO.File.ReadAllText(fixturePath, Encoding.UTF8).TrimEnd('\n', '\r');

    bool eq = got02 == expect02;
    Console.WriteLine($"02 plaintext 逐字节复刻样本 : {(eq ? "PASS 逐字节一致" : "FAIL")}");
    Console.WriteLine($"  长度 got={got02.Length}  expect={expect02.Length}");
    if (!eq)
    {
        int n = Math.Min(got02.Length, expect02.Length);
        int diff = 0;
        while (diff < n && got02[diff] == expect02[diff]) diff++;
        int s = Math.Max(0, diff - 40);
        Console.WriteLine($"  首个差异 @ {diff}");
        Console.WriteLine($"    got   : ...{got02.Substring(s, Math.Min(120, got02.Length - s))}");
        Console.WriteLine($"    expect: ...{expect02.Substring(s, Math.Min(120, expect02.Length - s))}");
    }

    // 用固定 random 生成 body, 验证外层 encryptInfo 包装结构。
    // (plaintext 已逐字节复刻样本 + AES 为确定性, 故 data 段必与样本一致, 此处只查结构)
    var clientSample = new RegisterClient(sampleDev);
    string body02 = clientSample.BuildBody02(samplePddid, PddBodyCrypto.FixedRandom32,
        sampleCurrent, sampleActive, sampleProcId, 89703556, 89704308);
    bool wrapOk = body02.StartsWith("{\"encryptInfo\":\"{\\\"key\\\":\\\"")
                  && body02.Contains("\\\"data\\\":\\\"")
                  && body02.EndsWith(",\"collect_begin_time\":89703556,\"collect_end_time\":89704308}");
    Console.WriteLine($"\n02 body 外层 encryptInfo 包装结构 : {(wrapOk ? "PASS" : "FAIL")}");
    Console.WriteLine($"  body 长度 = {body02.Length}");
    Console.WriteLine($"  body 头部 : {body02[..Math.Min(90, body02.Length)]}...");
}

Console.WriteLine("\n================ 7. 两台 mock 设备 02 报文数据 (并排 diff) ================\n");

void DumpDevice02(string fileName, DeviceProfile dev)
{
    const string pddid = "MOCKPDID";  // 实际由 01 响应下发, 此处占位
    long current = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    long active = current - dev.BootTime * 1000;   // 与设备 boot_time 自洽 (= 01 报文 boot_time)
    int procId = Random.Shared.Next(300, 30000);

    byte[] pt = Extra02Builder.BuildPlaintext(dev, pddid, current, active, procId);
    string plaintext = Encoding.UTF8.GetString(pt);

    // 解析 53 字段 (顶层 JSON) 供逐字段对比
    using var doc = System.Text.Json.JsonDocument.Parse(plaintext);
    var fields = new List<object>();
    int idx = 0;
    foreach (var p in doc.RootElement.EnumerateObject())
        fields.Add(new { i = idx++, k = p.Name, v = p.Value.ToString() });

    var obj = new
    {
        android_id = dev.AndroidId,
        install_token = dev.InstallToken,
        pddid,
        process_id = procId,
        currentTime = current,
        activeTime = active,
        fieldCount = idx,
        fields
    };
    var jsonOpts = new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    string json = System.Text.Json.JsonSerializer.Serialize(obj, jsonOpts);
    string path = System.IO.Path.Combine(outDir2, fileName);
    System.IO.File.WriteAllText(path, json, new UTF8Encoding(false));

    // 同时落盘原始明文 JSON (与真机解密结果直接 diff)
    string rawPath = System.IO.Path.Combine(outDir2, fileName.Replace(".json", "_plaintext.json"));
    System.IO.File.WriteAllText(rawPath, plaintext, new UTF8Encoding(false));
    Console.WriteLine($"  已写出: {path}");
    Console.WriteLine($"          {rawPath}");
}

DumpDevice02("mock_02_device_1.json", DeviceMocker.NewDevice());
DumpDevice02("mock_02_device_2.json", DeviceMocker.NewDevice());
Console.WriteLine("\n  对比建议: 02 唯一性字段 (pddid/install_token/android_id/fingerprint 等) 两文件应符合预期;");
Console.WriteLine("            机型/环境字段 (board/cpu/sensor/lib_list/p30 应用清单等) 两文件应完全相同。");

// ================================================================
// 8. 03 报文 (extra/data_type=20, 双层 SE.us) 验证 + 两台 mock 设备数据
// ================================================================
Console.WriteLine("\n================ 8. 03 内层逐字节复刻验证 (干净真机基线) ================\n");
{
    string fixturePath = System.IO.Path.Combine(AppContext.BaseDirectory, "sample_03_inner_clean.json");
    string expect03 = System.IO.File.ReadAllText(fixturePath, Encoding.UTF8).TrimEnd('\n', '\r');

    // 从基线里取出 rand 值, 喂给 Builder 以便逐字节比对 (rand 否则每次随机)
    using var bdoc = System.Text.Json.JsonDocument.Parse(expect03);
    string baseRand = bdoc.RootElement.GetProperty("rand").GetString()!;

    var sampleDev = DeviceProfile.FromSample01();   // AdbEnabled=1 → adb_status=running, 与真机基线一致
    byte[] inner = Extra03Builder.BuildInnerPlaintext(sampleDev, randB64: baseRand);
    string got03 = Encoding.UTF8.GetString(inner);

    bool eq = got03 == expect03;
    Console.WriteLine($"03 内层 plaintext 逐字节复刻干净真机 : {(eq ? "PASS 逐字节一致" : "FAIL")}");
    Console.WriteLine($"  长度 got={got03.Length} expect={expect03.Length}  字段数=24 (无 AB 门控组)");
    if (!eq)
    {
        int n = Math.Min(got03.Length, expect03.Length), diff = 0;
        while (diff < n && got03[diff] == expect03[diff]) diff++;
        int s = Math.Max(0, diff - 40);
        Console.WriteLine($"  首个差异 @ {diff}");
        Console.WriteLine($"    got   : ...{got03.Substring(s, Math.Min(120, got03.Length - s))}");
        Console.WriteLine($"    expect: ...{expect03.Substring(s, Math.Min(120, expect03.Length - s))}");
    }
}

Console.WriteLine("\n================ 9. 两台 mock 设备 03 报文数据 (并排 diff) ================\n");

void DumpDevice03(string fileName, DeviceProfile dev)
{
    const string pddid = "MOCKPDID";  // 实际由 01 响应下发
    byte[] inner = Extra03Builder.BuildInnerPlaintext(dev);    // rand 随机, adb 联动
    string innerJson = Encoding.UTF8.GetString(inner);

    using var doc = System.Text.Json.JsonDocument.Parse(innerJson);
    var fields = new List<object>();
    int idx = 0;
    foreach (var p in doc.RootElement.EnumerateObject())
        fields.Add(new { i = idx++, k = p.Name, v = p.Value.ToString() });

    // 外层 (内层包用占位固定 key 加密) — 仅展示结构
    var client = new RegisterClient(dev);
    string innerPkg = client.BuildInner03Package(PddBodyCrypto.FixedRandom32);
    byte[] outer = Extra03Builder.BuildOuterPlaintext(pddid, innerPkg);
    string outerJson = Encoding.UTF8.GetString(outer);

    var obj = new
    {
        android_id = dev.AndroidId,
        pddid,
        adb_enabled = dev.AdbEnabled,
        fingerprint = dev.Fingerprint,
        innerFieldCount = idx,
        innerFields = fields,
        outerPlaintext = outerJson
    };
    var opts = new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    string json = System.Text.Json.JsonSerializer.Serialize(obj, opts);
    string path = System.IO.Path.Combine(outDir2, fileName);
    System.IO.File.WriteAllText(path, json, new UTF8Encoding(false));
    System.IO.File.WriteAllText(path.Replace(".json", "_inner_plaintext.json"), innerJson, new UTF8Encoding(false));
    Console.WriteLine($"  已写出: {path}");
    Console.WriteLine($"          {path.Replace(".json", "_inner_plaintext.json")}");
}

DumpDevice03("mock_03_device_1.json", DeviceMocker.NewDevice());
DumpDevice03("mock_03_device_2.json", DeviceMocker.NewDevice());
Console.WriteLine("\n  对比建议: 03 内层 rand 两文件应不同(随机); model_sys_fingerprint 应=01 fingerprint;");
Console.WriteLine("            adb_status/adb_enabled 应反映 mock 干净设备(stopped/0); 其余 clean 基线两文件相同。");
Console.WriteLine("            注意: 不含 8f70d/5b766/y5dx/zt12t/zddgq (AB 门控组, 真机当前也不发)。");

// ================================================================
// 10. 04 报文 (meta_info/meta_type=all) 验证 + 两台 mock 设备数据
// ================================================================
Console.WriteLine("\n================ 10. 04 plaintext 逐字节复刻验证 (样本设备) ================\n");
{
    var sampleDev = DeviceProfile.FromSample01();   // 机型/设备字段 = 样本基线
    var opt = Meta04Options.ForSample04();          // 会话/运行时 = 04 样本值
    byte[] pt04 = MetaInfoAllBuilder.BuildPlaintext(sampleDev, opt);
    string got04 = Encoding.UTF8.GetString(pt04);

    string fixturePath = System.IO.Path.Combine(AppContext.BaseDirectory, "sample_04_plaintext.txt");
    string expect04 = System.IO.File.ReadAllText(fixturePath, Encoding.UTF8).TrimEnd('\n', '\r');

    bool eq = got04 == expect04;
    Console.WriteLine($"04 plaintext 逐字节复刻样本 : {(eq ? "PASS 逐字节一致" : "FAIL")}");
    Console.WriteLine($"  token 数 got={got04.Split('&').Length} expect={expect04.Split('&').Length} (137)");
    Console.WriteLine($"  长度 got={got04.Length}  expect={expect04.Length}");
    if (!eq)
    {
        int n = Math.Min(got04.Length, expect04.Length), diff = 0;
        while (diff < n && got04[diff] == expect04[diff]) diff++;
        int s = Math.Max(0, diff - 50);
        Console.WriteLine($"  首个差异 @ {diff}");
        Console.WriteLine($"    got   : ...{got04.Substring(s, Math.Min(140, got04.Length - s))}");
        Console.WriteLine($"    expect: ...{expect04.Substring(s, Math.Min(140, expect04.Length - s))}");
    }
}

Console.WriteLine("\n================ 11. 两台 mock 设备 04 报文数据 (并排 diff) ================\n");

// PFieldsCodec 往返自检 (解密样本基线 → 重加密线格式应与样本一致)
{
    string[] fs = { "p50", "p65", "p85", "p53", "p68" };
    string[] baseWire = { MetaInfoAllBaseline.P50, MetaInfoAllBaseline.P65, MetaInfoAllBaseline.P85,
                          MetaInfoAllBaseline.P53, MetaInfoAllBaseline.P68 };
    bool allOk = true;
    Console.WriteLine("PFieldsCodec 往返自检 (解密样本 → 重加密 == 样本线格式):");
    for (int i = 0; i < fs.Length; i++)
    {
        string plain = PFieldsCodec.DecodeWire(fs[i], baseWire[i]);
        string reWire = PFieldsCodec.EncodeWire(fs[i], plain);
        bool ok = reWire == baseWire[i];
        allOk &= ok;
        string shown = plain.Length > 60 ? plain[..57] + "..." : plain;
        Console.WriteLine($"  {fs[i]} : {(ok ? "PASS" : "FAIL")}  明文='{shown}'");
    }
    Console.WriteLine($"  往返一致: {(allOk ? "全 PASS" : "有 FAIL")}\n");

    // mediaDrm 模板自检: 用样本 Widevine ID 重建应 == 样本基线 (保证只动 per-unit id)
    string mdSample = MetaInfoAllBuilder.BuildMediaDrmWire(
        "b4c70928139f4ff7ccec3f412ff221cb7f72d229598549fa5731be0c023b9bdc");
    Console.WriteLine($"mediaDrm 模板自检 (样本ID重建==基线): {(mdSample == MetaInfoAllBaseline.MediaDrm ? "PASS" : "FAIL")}");
    Console.WriteLine("  → mock 仅随机 Widevine deviceUniqueId(per-unit唯一); input_device hash 保持基线(按机型, 真机同型号相同)\n");
}


void DumpDevice04(string fileName, DeviceProfile dev)
{
    long now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
    dev.RecomputeUserEnv2(now, form: DeviceProfile.UserEnv2Form.Report04);   // 04: an/pk/extra 形态, 用新 android_id 重算

    // p85 与 fk_data 共享本次会话的 dynso 加载时间戳 (联动); p85 hexid 每台随机 5 字节
    long dynsoTs = now - Random.Shared.Next(2000, 12000);
    string dynsoRand = Random.Shared.NextInt64(0, 10_000_000_000L).ToString("D10");
    string p85Hex = DeviceMocker.RandomHex(5);              // 10 hex
    string p85Plain = PFieldsCodec.BuildP85Plain(dynsoTs, p85Hex);

    var opt = new Meta04Options
    {
        Pddid = "MOCKPDID",            // 实际由 01 响应下发
        KnownDevice = 0,               // 全新 mock 设备首注册
        Cookie = "",                   // 新设备无会话残留
        CurrentTimeMs = now,
        InstallTimeMs = dev.P46InstallTime,
        AppUpdateTimeMs = dev.P46InstallTime,
        BootTime = dev.BootTime,
        LocalSequence = 1,
        P26 = MetaInfoAllBaseline.P26Mock,   // 干净设备无用户 CA
        DynsoLoadTs = dynsoTs,
        // p85: 会话时间戳 + 随机 hexid 重算 (与 fk_data.dynso_load_ts 一致)
        P85 = PFieldsCodec.EncodeWire("p85", p85Plain),
        // mediaDrm: 按本设备 Widevine deviceUniqueId 重建 (per-unit 唯一, 防判重复设备)
        MediaDrm = MetaInfoAllBuilder.BuildMediaDrmWire(dev.MediaDrmWidevineId),
        // p50/p65/p53/p68: 应用/ROM 绑定, 复刻基线 (留 null → MetaInfoAllBaseline; 同 ROM 设备本应相同)
        FkData = FkDataBuilder.Build(dynsoTs, dynsoRand),  // dynso_load_ts 与 p85 联动
    };
    byte[] pt = MetaInfoAllBuilder.BuildPlaintext(dev, opt);
    string plaintext = Encoding.UTF8.GetString(pt);
    var toks = plaintext.Split('&');

    var tokens = new List<object>(toks.Length);
    for (int i = 0; i < toks.Length; i++)
    {
        int eq = toks[i].IndexOf('=');
        if (eq >= 0) tokens.Add(new { i, k = toks[i][..eq], v = toks[i][(eq + 1)..] });
        else tokens.Add(new { i, k = (string?)null, v = toks[i] });
    }
    // 加密大字段解密回显 (证明 mocker 正确处理 + 明文语义可见)
    var pfields = new
    {
        p50_plain = PFieldsCodec.DecodeWire("p50", opt.P50 ?? MetaInfoAllBaseline.P50),
        p65_plain = PFieldsCodec.DecodeWire("p65", opt.P65 ?? MetaInfoAllBaseline.P65),
        p85_plain = PFieldsCodec.DecodeWire("p85", opt.P85 ?? MetaInfoAllBaseline.P85),
        p53_plain = PFieldsCodec.DecodeWire("p53", opt.P53 ?? MetaInfoAllBaseline.P53),
        p68_plain = PFieldsCodec.DecodeWire("p68", opt.P68 ?? MetaInfoAllBaseline.P68),
        dynso_load_ts = dynsoTs
    };
    var obj = new
    {
        android_id = dev.AndroidId,
        uuid = dev.Uuid,
        oaid = dev.Oaid,
        p47 = dev.P47,
        install_token = dev.InstallToken,
        media_drm_widevine_id = dev.MediaDrmWidevineId,
        known_device = opt.KnownDevice,
        pfields_decrypted = pfields,
        tokenCount = toks.Length,
        tokens
    };
    var jsonOpts = new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    string json = System.Text.Json.JsonSerializer.Serialize(obj, jsonOpts);
    string path = System.IO.Path.Combine(outDir2, fileName);
    System.IO.File.WriteAllText(path, json, new UTF8Encoding(false));
    System.IO.File.WriteAllText(path.Replace(".json", "_plaintext.txt"), plaintext, new UTF8Encoding(false));
    Console.WriteLine($"  已写出: {path}");
    Console.WriteLine($"          {path.Replace(".json", "_plaintext.txt")}");
}

DumpDevice04("mock_04_device_1.json", DeviceMocker.NewDevice());
DumpDevice04("mock_04_device_2.json", DeviceMocker.NewDevice());
Console.WriteLine("\n  对比建议: 04 唯一性字段 (android_id/oaid/uuid/p47/p10/install_token/user_env2/p125) 两文件应不同;");
Console.WriteLine("            机型/环境基线 (p2/p6/p13/p16/p20/p31/p32/input_device/mediaDrm 等) 两文件应完全相同;");
Console.WriteLine("            p26 应为空(干净), known_device=0(新设备), fk_data.inline_hook=干净基线。");

// ================================================================
// 12. 05 报文 (extra/data_type=17, wtp) 验证 + 两台 mock 设备数据
// ================================================================
Console.WriteLine("\n================ 12. 05 plaintext 逐字节复刻验证 (样本设备) ================\n");
{
    const string samplePddid = "WqfIGg5r";
    // 样本 wtp = 失败形态 (无 IP); 逐字节复刻样本须用样本原值
    byte[] pt05 = Extra05Builder.BuildPlaintext(samplePddid, Extra05Builder.SampleWtp);
    string got05 = Encoding.UTF8.GetString(pt05);

    string fixturePath = System.IO.Path.Combine(AppContext.BaseDirectory, "sample_05_plaintext.txt");
    string expect05 = System.IO.File.ReadAllText(fixturePath, Encoding.UTF8).TrimEnd('\n', '\r');

    bool eq = got05 == expect05;
    Console.WriteLine($"05 plaintext 逐字节复刻样本 : {(eq ? "PASS 逐字节一致" : "FAIL")}");
    Console.WriteLine($"  长度 got={got05.Length} expect={expect05.Length}  (version=整数, data_type=字符串\"17\", wtp 的 / 转义)");
    if (!eq)
    {
        int n = Math.Min(got05.Length, expect05.Length), diff = 0;
        while (diff < n && got05[diff] == expect05[diff]) diff++;
        int s = Math.Max(0, diff - 40);
        Console.WriteLine($"  首个差异 @ {diff}");
        Console.WriteLine($"    got   : ...{got05.Substring(s, Math.Min(120, got05.Length - s))}");
        Console.WriteLine($"    expect: ...{expect05.Substring(s, Math.Min(120, expect05.Length - s))}");
    }

    // 外层包装结构 (仅 encryptInfo, 无 collect_*time)
    var clientSample = new RegisterClient(DeviceProfile.FromSample01());
    string body05 = clientSample.BuildBody05(samplePddid, PddBodyCrypto.FixedRandom32, Extra05Builder.SampleWtp);
    bool wrapOk = body05.StartsWith("{\"encryptInfo\":\"{\\\"key\\\":\\\"")
                  && body05.Contains("\\\"data\\\":\\\"")
                  && body05.EndsWith("\"}") && !body05.Contains("collect_begin_time");
    Console.WriteLine($"\n05 body 外层包装 (仅 encryptInfo, 无 collect_*time) : {(wrapOk ? "PASS" : "FAIL")}");
    Console.WriteLine($"  body 头部 : {body05[..Math.Min(80, body05.Length)]}...");
}

Console.WriteLine("\n================ 12b. WtpCodec 自检 (逐字节复现真实样本 + 往返) ================\n");
{
    // 用固定 (tag,key) 逐字节复现两个真实 wtp 样本
    string rep1 = WtpCodec.Encode("180.139.62.90", tag: 10, key: 0x8a);
    string rep2 = WtpCodec.Encode("180.139.62.90", tag: 5, key: 0xb7);
    const string sampleGum = "D8EAAAQEAAq69ruyuqS7ubOkiry4pLO69ro=";
    const string sampleObs = "D8EAAAQEAAWHy4aPh7eZhoSOmYGFmY6Hy4c=";
    Console.WriteLine($"  复现 gumtrace 样本 (tag10/key8a): {(rep1 == sampleGum ? "PASS" : "FAIL")}");
    Console.WriteLine($"  复现 observe  样本 (tag5/keyb7) : {(rep2 == sampleObs ? "PASS" : "FAIL")}");

    // 往返: 任意 IP 编码 → 解码应还原同 IP
    string[] ips = { "180.139.62.90", "1.1.1.1", "101.89.43.68", "255.255.255.255" };
    bool allOk = true;
    foreach (var ip in ips)
    {
        var d = WtpCodec.Decode(WtpCodec.Encode(ip));
        bool ok = d.ip == ip;
        allOk &= ok;
        Console.WriteLine($"  往返 {ip,-16} → 解出 ip={d.ip} tag={d.tag} key=0x{d.key:x2} {(ok ? "OK" : "FAIL")}");
    }
    Console.WriteLine($"  往返一致: {(allOk ? "全 PASS" : "有 FAIL")}");
}

Console.WriteLine("\n================ 12c. 两台 mock 设备 05 报文数据 (并排 diff) ================\n");

void DumpDevice05(string fileName, DeviceProfile dev)
{
    const string pddid = "MOCKPDID";  // 实际由 01 响应下发
    // wtp: 先固定用实测真实 IP (后续按 mock 出口实际解析 strc.pinduoduo.com 动态化)
    string wtp = WtpCodec.Encode(WtpCodec.DefaultIp);   // tag/key 随机, 解码同 IP
    byte[] pt = Extra05Builder.BuildPlaintext(pddid, wtp);
    string plaintext = Encoding.UTF8.GetString(pt);

    using var doc = System.Text.Json.JsonDocument.Parse(plaintext);
    var fields = new List<object>();
    int idx = 0;
    foreach (var p in doc.RootElement.EnumerateObject())
        fields.Add(new { i = idx++, k = p.Name, v = p.Value.ToString() });

    var wd = WtpCodec.Decode(wtp);
    var obj = new
    {
        android_id = dev.AndroidId,
        pddid,
        wtp,
        wtp_decoded = new { wd.tag, key = $"0x{wd.key:x2}", wd.plaintext, wd.ip },
        fieldCount = idx,
        fields
    };
    var opts = new System.Text.Json.JsonSerializerOptions
    {
        WriteIndented = true,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };
    string json = System.Text.Json.JsonSerializer.Serialize(obj, opts);
    string path = System.IO.Path.Combine(outDir2, fileName);
    System.IO.File.WriteAllText(path, json, new UTF8Encoding(false));
    System.IO.File.WriteAllText(path.Replace(".json", "_plaintext.json"), plaintext, new UTF8Encoding(false));
    Console.WriteLine($"  已写出: {path}");
    Console.WriteLine($"          {path.Replace(".json", "_plaintext.json")}  (wtp 解出 ip={wd.ip})");
}

DumpDevice05("mock_05_device_1.json", DeviceMocker.NewDevice());
DumpDevice05("mock_05_device_2.json", DeviceMocker.NewDevice());
Console.WriteLine("\n  对比建议: 05 固定头字段两文件应相同 (version=1/data_type=\"17\"/platform);");
Console.WriteLine("            pddid 由 01 下发; wtp 两文件 base64 不同(随机 tag/key)但解码同 IP(180.139.62.90)。");
Console.WriteLine("            wtp IP 暂固定, 后续按 mock 出口实际解析 strc.pinduoduo.com 动态化。");

Console.WriteLine("\n=== 完成 (未发送任何网络请求) ===");
return 0;

static void PrintSection(string title) => Console.WriteLine(title);

static void Row(string name, string sampleVal, string mockVal)
{
    bool changed = sampleVal != mockVal;
    string tag = changed ? "[变]" : "[同]";
    Console.WriteLine($"  {tag} {name}");
    Console.WriteLine($"        样本: {Trunc(sampleVal)}");
    Console.WriteLine($"        mock: {Trunc(mockVal)}");
}

static string Trunc(string s)
{
    if (string.IsNullOrEmpty(s)) return "(空)";
    return s.Length > 96 ? s[..96] + "…(+" + (s.Length - 96) + ")" : s;
}

static string GetIdx(string[] arr, int i) => i < arr.Length ? (arr[i].Length == 0 ? "(空)" : arr[i]) : "(无)";

// user_env2 解密: TEA-CBC 变体的逆 (验证用)
static string DecryptUserEnv2(string b64)
{
    string padded = b64;
    int mod = padded.Length % 4;
    if (mod != 0) padded += new string('=', 4 - mod);
    byte[] ct = Convert.FromBase64String(padded);
    byte[] pt = TeaCbcDecrypt(ct, UserEnv2Codec.KeyA5_0);
    // 去零填充
    int end = pt.Length;
    while (end > 0 && pt[end - 1] == 0) end--;
    return Encoding.ASCII.GetString(pt, 0, end);
}

// TEA-CBC 变体解密 (UserEnv2Codec 加密的逆向)
static byte[] TeaCbcDecrypt(byte[] ct, byte[] key)
{
    const uint Mask = 0xFFFFFFFF;
    const uint IvV18 = 848835678u;
    uint IvV17 = unchecked((uint)(-317585009));
    const uint DeltaStep = 1640531527u;

    uint[] k = { ReadLE32(key, 0), ReadLE32(key, 4), ReadLE32(key, 8), ReadLE32(key, 12) };
    int blocks = ct.Length / 8;
    byte[] outp = new byte[ct.Length];
    uint prev18 = IvV18, prev17 = IvV17;

    for (int b = 0; b < blocks; b++)
    {
        uint c0 = ReadLE32(ct, 8 * b);
        uint c1 = ReadLE32(ct, 8 * b + 4);
        uint v18 = c0, v17 = c1;
        uint sum = 0xC6EF3720u; // delta*32
        for (int r = 0; r < 32; r++)
        {
            v17 = unchecked(v17 - (((k[2] + ((v18 << 4) & Mask)) & Mask)
                                  ^ ((sum + v18) & Mask)
                                  ^ ((k[3] + (v18 >> 5)) & Mask))) & Mask;
            v18 = unchecked(v18 - (((k[0] + ((v17 << 4) & Mask)) & Mask)
                                  ^ ((v17 + sum) & Mask)
                                  ^ ((k[1] + (v17 >> 5)) & Mask))) & Mask;
            sum = unchecked(sum + DeltaStep) & Mask;
        }
        uint p0 = (v18 ^ prev18) & Mask;
        uint p1 = (v17 ^ prev17) & Mask;
        WriteLE32(outp, 8 * b, p0);
        WriteLE32(outp, 8 * b + 4, p1);
        prev18 = c0; prev17 = c1;
    }
    return outp;
}

static uint ReadLE32(byte[] b, int o)
    => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));

static void WriteLE32(byte[] b, int o, uint v)
{
    b[o] = (byte)v; b[o + 1] = (byte)(v >> 8);
    b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24);
}
