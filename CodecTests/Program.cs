using System.Text;
using PddLib.Crypto;
using PddLib.Crypto.Extra;
using PddLib.Register;
using PddLib.H5;

// ============================================================
// C 类 native 自产字段 codec 往返/正向验证
//   - user_env2 (TEA-CBC + base64)
//   - p30       (RC4 + base64 + urlencode)
//   - p47       (随机会话标识生成 + 格式校验)
// 全部对照真机样本逐字节验证。
// ============================================================

Console.OutputEncoding = Encoding.UTF8;
int pass = 0, fail = 0;
void Check(string name, bool ok, string? detail = null)
{
    Console.WriteLine($"[{(ok ? "PASS" : "FAIL")}] {name}{(detail != null ? "  " + detail : "")}");
    if (ok) pass++; else fail++;
}

Console.WriteLine("==== user_env2 (SE.ues, TEA-CBC) ====");
{
    // 真机样本: android_id=5358b6fd9144e561, ts=1780860636109
    const string androidId = "5358b6fd9144e561";
    const long ts = 1780860636109;
    const string expect =
        "pvBKsTDrqP4Lc8iUMZoXWgRFbnPKWC7afULTzYNugbWsQXhhLR1WuRBNiife+l4XJH65PgcFo7B4tZWprkz84SNBQNv5I10L";

    string got = UserEnv2Codec.Generate(androidId, ts, seq: 0, ver: "2.2.1");
    Check("user_env2 正向生成 == 真机样本", got == expect);
    if (got != expect)
    {
        Console.WriteLine($"  期望: {expect}");
        Console.WriteLine($"  实际: {got}");
    }

    // 明文组装检查
    string pt = UserEnv2Codec.BuildPlaintext(androidId, ts);
    Check("user_env2 明文 JSON 结构", pt == "{\"id\":\"5358b6fd9144e561\",\"ts\":1780860636109,\"seq\":0,\"ver\":\"2.2.1\"}", pt);

    // 换 android_id 应得到不同 user_env2 (设备绑定证明)
    string other = UserEnv2Codec.Generate("0000000000000000", ts);
    Check("换 android_id → user_env2 变化 (设备绑定)", other != got);
}

Console.WriteLine("\n==== user_env2 可变 schema 形态 (01/04/06 逐字节复刻真机样本) ====");
{
    const string id = "5358b6fd9144e561";

    // —— 01 (meta_type=sub): 含 "4" ——
    const string sample01 = "fKngCeNhzVcydUeyFLBk3BSFNjN9bh8bwfE+QgRqp68/DG+ZDINxieLbDmIF9oN2Wdv4E4OP12mygtxWnG+c+VtZk1mZTArGDyx1dt/Df/Qy4V/UML6sI4T8PCK4azd2";
    string got01 = UserEnv2Codec.GenerateFrom(UserEnv2Codec.Form01(id, 1780084169108, 0));
    Check("01 形态 (Form01) == 样本", got01 == sample01.TrimEnd('='), got01);

    // —— 04 (meta_type=all, scene=1): an=0 + pk + extra="" ——
    const string sample04 = "416AiYYGHAkkchgVbxdqqFohpYZSFDUa27UTeAVFwGPGHs2gmcwvQ5/sMn2X7GDDKiDF3kqesAom2/wg4NW6/XAmhHk5mWsv4IjtkHQH4sdN2xpt7j/luNkLXnGK03rTuqxg48hjDYDvwoSth7zAhRgUivGvhp3nfP1UIpB6lz0JstU+rx0BqipfR/bDggje";
    string got04 = UserEnv2Codec.GenerateFrom(UserEnv2Codec.Form04(id, 1780084170380, 10));
    Check("04 形态 (Form04) == 样本", got04 == sample04.TrimEnd('='), got04);

    // —— 06 (meta_type=all, scene=14): 4 + 8 + an=8 + pk + extra(libdyncommon 容器) ——
    const string realtime06 = "0||1904x1520|16515|1";
    const string extra06 = "01D8EAABAIAzACRkJ551SPBcAAsiN9hu1T3xmSoL+Vk+7BiLZ0woqMd8qT3EPd5/e7Ku+8Z8w54EohyI9gJ1Yokeu+AH1M+gjfayoMwclJIXap/U9LHB1o7UKdjEZ7/10htdCZrQmbKjucP7B8C4l1RrywDvBS83iHejq0yUP+LjgGdlM1PmNKw8UyaygxtsiY48tm6n7MyY3Ad+NowismkfkXsB6Xp34KVhZUqlHUb1a5s2pN95qcFe52sLE0iNh32j0oywnasn5besrP1Br1yyB4mjWtq/hxeY+utyVhM6yONmOTHYu0JaYqT2vTkk8Oq4s3xaIhfgJOBHVeKjKg7hZuDpXzgncwjrl0yMZuDCCRDnzFtKujT3LfufFIQPXbEUA/cACjfgEO4UTVJZ0J4TAD/0rwZBscAYkuxjEafWhhw06m6FD1YRsp+tN1WW6mECiRA6NK1E2MwrV2LiYmv34PVjJl/f1ELMy53iKXkMBtnLa+hP/FF+ANNyKCRclvd3rYfA/N9r+fOJJAT3Gdw60kC9R++vEy6PjBji9iBn1XmBraZ2vrNMR10LYK8ud2pr/GJXFkwbJEwaaFSGq4FKWT6NdQJs+peNI0tQuyxUvgK1PuJULDbf9Cn/eVQKgdnfIpaFAaKan2q3/gltivR3CjB3aq65sb79KcW9obokVNg95AqQXhGITih7rVYKBQutzUnDOW7vc2WbBJqcvFn2JTI1a/L+G5pEKK2mHBUsUbs02EqbDD5PE+KTPu2nicPR+PZaTH3QeI5sJ+lgGC7AAGCT+24pFSmjt755Xtes7xa0c72D1+XemR6IpKkAzccrMntbXknOC3vQinmIjyy97cmgw1poi/yYtDmvK7EPr3nRVisMGZjm9xQR2WVwAUmTvAJbAgeOMnT9xUwkSG04o1eNt3tHmZ6Uy4CE9pxyAvO3TbMqieNDa9TXYAHBUTKeC1q+GPEqrnRdeWjfHLdzCl9RT+JUu7b7SmrJSfnHXId9t+aZez7MsKle/XNWERt4E0YShFbyX6Qtw0MnHg/ubEF6UDujUPuacDjLi1caipR/e9x5B3NdOXJ7uVVFK+3mAQLMOtbIRL2gAIAXbKFQQqttNAKJQ5eXJzEgfkCsLYAJmEMt7Q3yzny9llUuprzn0bI6MLiA1ORhNC3Gig/eOMbY8H6/FYHSnQwSXgsG6C1isAcRl1y0Zd7XiwIXCIA5/Q2mUqQqsG52FZjVzZ5zMdLclvLLjajQ3OMSc0ksV2qJ3H7HbJPd2b+rkQsuHY7IDFseTePNnu7zM2ZmfU8PAy7hw6Rlu9hrSGh/7CH6spKWe8Re5vF53rktF9vUYeq29iwS9svSG1JOfibUrRUSyPEGW3TbLDmdmtLdE2gTVenq6FGMyvoT4Z28APbY1WjYvfIBmetum+8xRqIENi4wmo4p/6AERZaFq/D5NxE1VSOoF5s/zqDrMSK0TGX3G9VJzh4p45kHBN1Xx+GIYMNzkIyqND7veP9U4PduFV86QtOhRuLIgdxCzS948KnzA+";
    const string sample06 = "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";
    string got06 = UserEnv2Codec.GenerateFrom(UserEnv2Codec.Form06(id, 1780084174940, 11, realtime06, extra06));
    Check("06 形态 (Form06) == 样本", got06 == sample06.TrimEnd('='), got06.Length.ToString());

    // 解密往返: 样本 → 明文 → 顶层含 id; 重建明文一致
    string plain06 = UserEnv2Codec.Decrypt(sample06);
    Check("06 解密明文含 android_id", plain06.Contains("\"id\":\"" + id + "\""));
    Check("06 解密往返 == Build06 明文",
        plain06 == UserEnv2Codec.BuildPlaintext(UserEnv2Codec.Form06(id, 1780084174940, 11, realtime06, extra06)));
}

Console.WriteLine("\n==== p30 (SecureNative.alm, RC4) ====");
{
    // 真机样本: 风险应用 com.zhenxi.hunter:1773686850901;
    const string sampleB64 = "OT70o9b7xtqXkanvAW7PJm4E5+NkmuGn6y0Ym7k3cAg42lZQ";
    const string riskPlain = "com.zhenxi.hunter:1773686850901;";

    // 1) 解密样本 → 明文 (urlencode 后)
    string decoded = P30Codec.DecryptBase64(sampleB64);
    string expectDecoded = "com.zhenxi.hunter%3A1773686850901%3B";
    Check("p30 解密 == urlencode(风险列表)", decoded == expectDecoded, decoded);

    // 2) 正向重建 base64 == 样本
    string got = P30Codec.GenBase64(riskPlain);
    Check("p30 正向 base64 == 真机样本", got == sampleB64);
    if (got != sampleB64)
    {
        Console.WriteLine($"  期望: {sampleB64}");
        Console.WriteLine($"  实际: {got}");
    }

    // 3) 往返: 由风险项列表生成 → 解密回明文
    var apps = new[] { new P30Codec.RiskApp("com.zhenxi.hunter", 1773686850901) };
    string built = P30Codec.GenBase64(P30Codec.BuildRiskList(apps));
    string roundtrip = P30Codec.DecryptBase64(built);
    Check("p30 往返 (列表→base64→解密)", roundtrip == expectDecoded, roundtrip);

    // 4) 报文字段 (外层 urlencode, '+' → %2B 等)
    string field = P30Codec.GenReportField(riskPlain);
    Check("p30 报文字段外层 UrlEncode", field == P30Codec.UrlEncode(sampleB64), field);

    // 5) 空列表 (mock 干净设备)
    string empty = P30Codec.GenBase64("");
    Check("p30 空列表可生成 (mock 干净设备)", empty.Length == 0 || empty != null, $"empty='{empty}'");
}

Console.WriteLine("\n==== p47 (native 自产随机会话标识) ====");
{
    // 真机样本格式校验
    Check("p47 样本1 格式合法", P47Generator.IsValid("S5n3Bd6L-ofNf-Zv3q-402e-4yHlPVhy5foo"));
    Check("p47 样本2 格式合法", P47Generator.IsValid("wJtHZtwB-C0Wz-OVhn-627d-0AFZBt7ErTKC"));
    Check("p47 非法格式被拒 (段数不符)", !P47Generator.IsValid("abc-def-ghi"));
    Check("p47 非法格式被拒 (含非法字符)", !P47Generator.IsValid("S5n3Bd6L-ofN!-Zv3q-402e-4yHlPVhy5foo"));
    // 注: 标准 UUID 也符合 8-4-4-4-12+[A-Za-z0-9], IsValid 仅校验格式不区分 hex/混合

    // 生成 1000 个, 全部格式合法且互不相同
    var seen = new HashSet<string>();
    bool allValid = true;
    for (int i = 0; i < 1000; i++)
    {
        string p = P47Generator.New();
        if (!P47Generator.IsValid(p)) { allValid = false; Console.WriteLine($"  非法: {p}"); break; }
        seen.Add(p);
    }
    Check("p47 生成 1000 个全部格式合法", allValid);
    Check("p47 生成 1000 个互不相同 (随机)", seen.Count == 1000, $"unique={seen.Count}");

    // MD5(p47) 作 x-p1 RC4 key = 16 字节
    string sample = "wJtHZtwB-C0Wz-OVhn-627d-0AFZBt7ErTKC";
    byte[] k = P47Generator.Md5Key(sample);
    Check("p47 → MD5 key 16 字节 (x-p1 RC4 key)", k.Length == 16);

    Console.WriteLine($"  示例生成: {P47Generator.New()}");
}

Console.WriteLine("\n==== extra(1008) 容器编解码 (迁移冒烟, KeyTable + 分帧 + 静态 keystream, 不依赖 Unicorn) ====");
{
    // 真机 _b 容器 (105B) + 已知 keystream (unidbg patch-seed dump 前 80B)
    byte[] bContainer = Extra1008Codec.HexToBytes(
        "0fc100001008002b004d4279f1e04296" + "1000231fc38e6fc7700e6a702bf19b19" +
        "bf4c22d0e64d5a50130787d32e1e157b" + "eeb8df891e000501daa4c8c67cb0f2c9" +
        "3d7e3a7ba635fb3128079188e93b32a2" + "0b2a64b71527d000050d28852652bb81" +
        "3f2be3da2ca517dd35");
    byte[] bKeystream = Extra1008Codec.HexToBytes(
        "583db1ef01a35234483413b4da58fe1d" + "6791a7151c287055e6e11646574db8e1" +
        "e2ab3286bdb519c297a74b5c00008401" + "d90b5325a3aad360108056064684371d" +
        "8ba7040fc6ad1d5886ab0e9f23a048e7");
    byte[] bSeed = Seed.FromHex("4279f1e042961000f96fc8e1c7ce8ac6");
    const string bPlain = "{\"rand\":\"D8EAAAQEAAXFxcRa28XB6VY=\",\"userenv\":{\"4\":{\"2\":[\"\"],\"3\":[\"\"]},\"seq\":4}}";

    // 1) KeyTable 从容器索引查表得 KEY_8B (数据文件已随输出复制)
    var keyTable = KeyTable.LoadDefault();
    var w0 = Index3.FromMarker(bContainer.AsSpan(53, 4)); // (5,1,218)
    var w1 = Index3.FromMarker(bContainer.AsSpan(87, 4)); // (5,13,40)
    string key8 = Convert.ToHexString(keyTable.DeriveKey8(w0, w1)).ToLowerInvariant();
    Check("KeyTable 索引→KEY_8B == f96fc8e1c7ce8ac6", key8 == "f96fc8e1c7ce8ac6", key8);

    // 2) 分帧解析: _b 标准变体 (counter@16:18, body@18)
    var fb = Extra1008Codec.ParseFraming(bContainer);
    Check("_b 分帧 = 标准变体 (body@18, 无头部标记)", fb.BodyStart == 18 && fb.HeaderWord0Pos == -1,
        $"body@{fb.BodyStart} hdrW0@{fb.HeaderWord0Pos} counter={Convert.ToHexString(fb.Counter).ToLowerInvariant()}");

    // 3) 用静态 keystream 走全自动解密, 应得干净 JSON
    var ksGen = new StaticKeystreamGenerator().Add(bSeed, bKeystream);
    var codec = new Extra1008Codec(keyTable, ksGen);
    var r = codec.DecryptAuto(bContainer);
    Check("_b DecryptAuto 明文 == 期望 JSON", r.PlaintextUtf8 == bPlain, r.PlaintextUtf8);
    Check("_b DecryptAuto KEY_8B 一致", Convert.ToHexString(r.Key8).ToLowerInvariant() == "f96fc8e1c7ce8ac6");

    // 4) _d 头部标记变体的分帧识别 (仅结构, 不需 keystream)
    byte[] dHead = Extra1008Codec.HexToBytes("0fc100001008000600a24279ec701d4800010ee98000e3fb");
    var fd = Extra1008Codec.ParseFraming(dHead);
    Check("_d 分帧 = 头部标记变体 (word0@16, counter@20:22, body@22)",
        fd.HeaderWord0Pos == 16 && fd.BodyStart == 22 && Convert.ToHexString(fd.Counter).ToLowerInvariant() == "8000",
        $"body@{fd.BodyStart} hdrW0@{fd.HeaderWord0Pos} counter={Convert.ToHexString(fd.Counter).ToLowerInvariant()}");

    // 5) 基于 lenflag 的确定性解码 (无启发式): 标记偏移由 lenflag 读出
    var lf = Extra1008Codec.ParseLenflag(bContainer);
    Check("_b lenflag 定位标记 = @53/@87", lf.Word0MarkerOffset == 53 && lf.Word1MarkerOffset == 87,
        $"w0@{lf.Word0MarkerOffset} w1@{lf.Word1MarkerOffset}");
    var rl = codec.DecryptByLenflag(bContainer);
    Check("_b DecryptByLenflag 明文 == 期望 JSON", rl.PlaintextUtf8 == bPlain);

    // 6) ★ 编码方向逐字节往返: Encrypt(明文, 观测偏移) == 原始容器
    byte[] ptBytes = Encoding.UTF8.GetBytes(bPlain);
    byte[] nonce = bContainer[12..16];
    byte[] counter = bContainer[16..18];
    byte[] reenc = codec.Encrypt(ptBytes, nonce, counter, w0, w1, 53, 87);
    Check("_b Encrypt 逐字节往返 == 原始容器",
        Convert.ToHexString(reenc) == Convert.ToHexString(bContainer),
        $"{reenc.Length}B vs {bContainer.Length}B");

    // 7) mock 便捷编码 → 解回明文 (自动选标记位, lenflag 定位)
    byte[] mock = codec.EncryptMock(ptBytes, nonce, counter, w0, w1);
    var rmock = codec.DecryptByLenflag(mock);
    Check("_b EncryptMock → DecryptByLenflag 明文一致", rmock.PlaintextUtf8 == bPlain,
        $"容器 {mock.Length}B");
}

Console.WriteLine("\n==== type15 es (SecureNative.dsi, RC4 keystream + XOR + base64) ====");
{
    // 真机 report_03 es (921B 密文, base64 1228 字符)
    const string sampleEs =
        "wZtnjfHzrGfb6jxWmZWsk4/M5aDvSnpLYa60uHlcqGP5zJqFR5SitmjAix3sk6eO5f7gQUgtPyAkWkWfcxMNK/OgF3bycRyYjbHeU0aMRVU3A2ilEebP1kWD4j7IA1SeAZbTaXbkYUbC3aydOvh954kVSL4FEcm3JAkWdx/ONdr7IIqhgpB/TwMcuK9g99D3mDIqY1ntNucQuwKLnuryJMzkfs7JfLgoipCncyPwCJE+kbbyGbQLM2dXiPUVs5eRsVL6SDqQzNDR9trHDvKxRhC42wadlo3yLVVy3xNCRwtydnlIURstvmDU+rbz5xW2viR0cTuD+LbzUDdE9XSEvlevV+LatAHro8+C9JAhGcj0+3lJDfBSm55HHjbONblI2Qlk/BMYiv1sOb/GXwxamwtu63d1fiRAkTxsVTubYqdvl75LXMBPROfGKSgTeEgMtqBVOjG6+k24WdfqzYQ/8igedLyOSBgxav8xsy5gV3PDDOpx14oxgmHZWteWMsXqxir33Ibi+hPZWeJkhBDRA97VS1TdVar19L4ZKOf0IdzdjmAoo1+n+0X4K35s6BqlZYNE5PRJkA/YQAfcBQnblOJTDhwf1pWrroXnWMMfxOOFFF3S1fzsllgtT26DwgQzZtmmPJTBakQphj4NKsnnNdHvr3s+XteqkTh9CMB/8RIvKKUs79zmN6byRpAAvbWvIzY8TxPuQ5jzyZC+0nfByvQMxgmbrsfhmrfAETRRFYQw3K3ijQ2e6Azhvlfbq+aVH2/C1x68fQId1XkHXnGhb3LuZdBeE/zGx0WsBeoysHEGbSD4+FVpnr9p2V2gofpPbgdRJlC6+bsZEKvNoNHt49EmjDUqj8duI43fcU0xbxgkRnXFoWjLjgc6jhTf3Idn/82X0PD+Xb9FXmhSd/C34MW0UoUS8e2vdkWx61YWcIolbC+ceoywI7yDIyTCdPQL9V+MSydQnGgVlO/aSH6gImefqghZPDoVdIfEP1p6Ry65VZSR8eO6ZFmuztUWf2OsEfBrvcvCSElLdFirliiC2EQcv9PzBX3vSTJfFi/eXrayq6sbixvHw8n4Ajo7pLLzk2uPxN96svyMxT/8CsdJ0NOQ5vFc1Z/ifXqspklRB8q6g9cPE/9AhwoOx53ONWr+4svRPMeJDe9wiqyeMNrY1qWT1tWFvjDsFHHsBZRLoW20B1TmlpGp7WfQ3i5PZW+W2+H3w1HzBZOB";

    // 1) RC4 keystream 前 16B == trace 坐实值
    string ks16 = Convert.ToHexString(Type15Codec.Keystream(16)).ToLowerInvariant();
    Check("type15 RC4 keystream[:16] == 坐实值", ks16 == "bab917bbc0d19656ecd20f6ea8a69aaa", ks16);

    // 2) 解真机 es (921B) → 完整合法明文
    string pt = Type15Codec.Decode(sampleEs);
    Check("type15 解密长度 == 921B", Encoding.UTF8.GetByteCount(pt) == 921, pt.Length.ToString());
    Check("type15 明文以 {\"p61\": 开头", pt.StartsWith("{\"p61\":1783813690041,\"p62\":{\"0\":\"3f2303d5ff8303d1fd7b08a9\""));
    Check("type15 明文以 \"p131\":4} 收尾", pt.EndsWith("\"p131\":4}"), pt.Substring(Math.Max(0, pt.Length - 24)));

    // 3) 逐字节往返: Encode(Decode(es)) == 原始 es
    Check("type15 往返 Encode∘Decode == 原始 es", Type15Codec.Encode(pt) == sampleEs);

    // 4) mock: 自造明文 → es → 解回一致
    string mockPt = "{\"p61\":1799999999000,\"p62\":{\"0\":\"\",\"8\":\"\"},\"p131\":2}";
    Check("type15 mock 明文往返一致", Type15Codec.Decode(Type15Codec.Encode(mockPt)) == mockPt);

    // 5) Type15Builder 逐字节复刻 report_03 (明文 + es)
    const string plain03 =
        "{\"p61\":1783813690041,\"p62\":{\"0\":\"3f2303d5ff8303d1fd7b08a9\",\"1\":\"3f2303d5ff8306d1fd7b14a9\",\"2\":\"3f2303d5ff8303d1fd7b08a9\",\"3\":\"3f2303d5ffc306d1fd7b15a9\",\"4\":\"3f2303d5ff8303d1fd7b08a9\",\"5\":\"3f2303d5ff8306d1fd7b14a9\",\"6\":\"3f2303d5ff4303d1fd7b07a9\",\"7\":\"3f2303d5ff4306d1fd7b13a9\",\"8\":\"5f2403d5e22800b43f2303d5\"},\"p63\":\"\",\"p64\":\"4040\",\"p69\":\"1\",\"p70\":\"f41042fb\",\"p71\":\"b09f677cd333cef2e771eec9448eeca77cc62879\",\"p73\":\"64\",\"p74\":\"evocpqAfyMlLu09Qlg3UPycANJP320TmoEYAftoz0urXMr/hkA4=\",\"p75\":\"sx19vJtmvbAvGdxbeHBOCSREqYwKr5oafR+BgOCu6MaWu85ZpJVGjFYVAYudRiO3ZfmU0WVgg2TUUdy9WsWBoqBnzo8aTPleVcMzClXXyt+sSzCT7i/5GGjOk4M=\",\"p82\":30290085,\"p83\":30035968,\"p84\":\"SW+urnbpru6b51wFwp/c\",\"p93\":\"VM6O6YQY7vPxtESpMKdA\",\"p94\":\"0\",\"p97\":\"1779712666437\",\"p98\":\"MBo+PlPLqS0CvfEjPVDlivZhVsJG385H1uh326KeYuS2hXIo4L9KxuKvx8NVz7GtXJ9cQPrA18xDDfCH+uhSGWk4e4uNBDI+oi0Vhn4EL0VWICMu82fmAnZdcx10cxQLeB1PhqYTP+48cTM9qOlva5z8YJA8MImC4b3c+bSisso=\",\"p131\":4}";
    string builtPt = Type15Builder.BuildEsPlaintext(new Type15Options());
    Check("Type15Builder 明文逐字节 == report_03", builtPt == plain03, builtPt.Length + " vs " + plain03.Length);
    Check("Type15Builder es == report_03 es", Type15Builder.BuildEs() == sampleEs);

    // 6) mock: 换 ts/类名/路径 → 解回应含新值
    var mo = new Type15Options { ReportTs = 1799000000123, P74Plain = "com.demo.App", P84Plain = "1799000000123_1" };
    string mockEs = Type15Builder.BuildEs(mo);
    var back = System.Text.Json.JsonDocument.Parse(Type15Codec.Decode(mockEs)).RootElement;
    Check("Type15Builder mock p61 生效", back.GetProperty("p61").GetInt64() == 1799000000123L);
    Check("Type15Builder mock p74 解回类名",
        Type15Codec.DecodeSubBlob(back.GetProperty("p74").GetString(), Type15Baseline.KsP74) == "com.demo.App");

    // 7) dv 开关: dv=18 无 p131 (17字段) / dv=19 有 (18字段)
    string pt18 = Type15Builder.BuildEsPlaintext(new Type15Options { Dv = 18 });
    string pt19 = Type15Builder.BuildEsPlaintext(new Type15Options { Dv = 19 });
    Check("Type15Builder dv=18 无 p131 且以 } 收尾", !pt18.Contains("\"p131\"") && pt18.EndsWith("}"));
    Check("Type15Builder dv=19 含 p131", pt19.Contains("\"p131\":4}"));
    var d18 = System.Text.Json.JsonDocument.Parse(pt18).RootElement;
    Check("Type15Builder dv=18 es 可解且字段数=17",
        System.Text.Json.JsonDocument.Parse(Type15Codec.Decode(Type15Codec.Encode(pt18))).RootElement.EnumerateObject().Count() == 17,
        d18.EnumerateObject().Count().ToString());
}

Console.WriteLine("\n==== apk 安装路径随机化 (type15.p75 ↔ type16 maps 联动一致) ====");
{
    var dev = DeviceMocker.NewDevice();
    // 1) 随机段 != 基线, 且 ApkPath 由两段拼出
    Check("mock 段1 已随机化 (!=基线)", dev.ApkDirSeg1 != DeviceProfile.BaselineApkSeg1, dev.ApkDirSeg1);
    Check("mock 段2 已随机化 (!=基线)", dev.ApkDirSeg2 != DeviceProfile.BaselineApkSeg2, dev.ApkDirSeg2);
    Check("ApkPath 由两段拼出",
        dev.ApkPath == $"/data/app/~~{dev.ApkDirSeg1}/com.xunmeng.pinduoduo-{dev.ApkDirSeg2}/base.apk");
    Check("ApkPath 长度 ≤ p75 keystream(117B)",
        System.Text.Encoding.UTF8.GetByteCount(dev.ApkPath) <= Type15Baseline.KsP75.Length,
        System.Text.Encoding.UTF8.GetByteCount(dev.ApkPath).ToString());

    // 2) es.p75 解回 == 设备 ApkPath
    string es = Type15Builder.BuildEs(new Type15Options { P75Plain = dev.ApkPath });
    var esObj = System.Text.Json.JsonDocument.Parse(Type15Codec.Decode(es)).RootElement;
    string p75 = Type15Codec.DecodeSubBlob(esObj.GetProperty("p75").GetString(), Type15Baseline.KsP75);
    Check("es.p75 解回 == 设备 ApkPath", p75 == dev.ApkPath, p75);

    // 3) type16 maps 用同一对随机段替换后, 与 p75 路径一致
    string maps = Type16Baseline.MapsRegions
        .Replace(DeviceProfile.BaselineApkSeg1, dev.ApkDirSeg1)
        .Replace(DeviceProfile.BaselineApkSeg2, dev.ApkDirSeg2);
    Check("type16 maps 含设备随机段 (与 p75 联动)",
        maps.Contains(dev.ApkDirSeg1) && maps.Contains(dev.ApkDirSeg2) && !maps.Contains(DeviceProfile.BaselineApkSeg1));
    Check("type16 maps 与 p75 同一安装目录前缀",
        maps.Contains($"/data/app/~~{dev.ApkDirSeg1}/com.xunmeng.pinduoduo-{dev.ApkDirSeg2}/"));
}

Console.WriteLine("\n==== type21 info (SecureNative.atn, RC4 keystream + XOR + base64) ====");
{
    // 1) RC4 keystream 前 16B == trace(unidbg-trace-atn.log) 逐字节坐实值
    string ks16 = Convert.ToHexString(Type21Codec.Keystream(16)).ToLowerInvariant();
    Check("type21 RC4 keystream[:16] == 坐实值", ks16 == "5a51998dac93a3b4eff887877400bb43", ks16);

    // 2) 解真机 08 info (6408B) → 100% 可打印合法 JSON {"0":"..."}
    string info = Extra0708Baseline.Info08;
    string pt = Type21Codec.Decode(info);
    Check("type21 解密长度 == 6408B", Encoding.UTF8.GetByteCount(pt) == 6408, Encoding.UTF8.GetByteCount(pt).ToString());
    Check("type21 明文以 {\"0\":\" 开头", pt.StartsWith("{\"0\":\""));
    Check("type21 明文以 \"} 收尾", pt.EndsWith("\"}"), pt.Substring(Math.Max(0, pt.Length - 8)));
    Check("type21 明文 100% 可打印",
        pt.All(c => (c >= ' ' && c <= '~') || c == '\n' || c == '\r' || c == '\t'));

    // 3) 逐字节往返: Encode(Decode(info)) == 原始 info
    Check("type21 往返 Encode∘Decode == 原始 info", Type21Codec.Encode(pt) == info);

    // 4) mock: 自造明文 → info → 解回一致 (任意长度)
    string mockPt = "{\"0\":\"MIIDkTCCAzegAwIBAgIBATAKBggqhkjOPQQDAj%2Fmock%3D\"}";
    Check("type21 mock 明文往返一致", Type21Codec.Decode(Type21Codec.Encode(mockPt)) == mockPt);

    // 5) Info08Builder: 明文重组 == 解密真机明文; info 逐字节 == 真机基线密文
    Check("Info08Builder 明文重组 == 解密真机明文", Info08Builder.BuildPlaintext() == pt);
    Check("Info08Builder info == report_08 基线密文", Info08Builder.BuildInfo() == info);
    Check("Info08Baseline 证书链 5 张", Info08Baseline.CertChain.Length == 5, Info08Baseline.CertChain.Length.ToString());
}

Console.WriteLine("\n==== info2 kernel(/proc/version) 随设备派生 (Info2Baseline.FromUname) ====");
{
    // 1) 基线 uname → 基线 KernelValue (逐字节 round-trip)
    const string baseUname = "Linux localhost 6.6.89-android15-8-g14220ae4ce65-ab13680582-4k #1 SMP PREEMPT Mon Jun 23 07:30:57 UTC 2025 aarch64 Toybox";
    Check("FromUname(基线uname) == 基线 KernelValue",
        Convert.ToBase64String(Info2Baseline.FromUname(baseUname)) == Info2Baseline.KernelValueB64);

    // 2) 不同设备 uname → 不同 KernelValue, 且含设备 release + 日期
    const string devUname = "Linux localhost 6.1.75-android14-11-g1234567890ab-ab12345678 #1 SMP PREEMPT_DYNAMIC Fri Sep 20 08:15:42 UTC 2024 aarch64 Toybox";
    byte[] kvDev = Info2Baseline.FromUname(devUname);
    string kvDevStr = Encoding.UTF8.GetString(kvDev, 1, kvDev.Length - 1);
    Check("异设备 KernelValue != 基线", Convert.ToBase64String(kvDev) != Info2Baseline.KernelValueB64);
    Check("KernelValue 含设备 release", kvDevStr.StartsWith("6.1.75-android14-11-g1234567890ab-ab12345678"));
    Check("KernelValue 含设备日期(去SMP/PREEMPT/空格)", kvDevStr.EndsWith("#1FriSep2008:15:42UTC2024"), kvDevStr.Substring(Math.Max(0, kvDevStr.Length - 26)));
    Check("KernelValue 首字节 0x0a", kvDev[0] == 0x0a);

    // 3) 解析失败/空 → 回落基线
    Check("空 uname 回落基线", Convert.ToBase64String(Info2Baseline.FromUname(null)) == Info2Baseline.KernelValueB64);
    Check("非法 uname 回落基线", Convert.ToBase64String(Info2Baseline.FromUname("garbage no linux")) == Info2Baseline.KernelValueB64);
}

Console.WriteLine("\n==== anti_content ('0as') 脱机编解码 (AntiContentCodec, 跨语言逐字节 vs JS ground truth) ====");
{
    // mock token + pre_deflate (JS dump_collectors.js 产出的 ground truth, 见 scripts/h5_tools/dump_collectors_out.json)
    const string mockToken =
        "0asAfa5E-wCEXxamXHSt_USOOG7qidIxXaGtmY6PI8Nj2GiiQqNFBti5fGm66HoXqbqauD4JnGPoHpmoXpXoU4OP0ginDbbqiDToX0TVtsrCpBroJA-QzoAdSkBeUeBVVE-VcEBeceBfKkLK7UK1z-eAkUK9T86Q4X4akurfje-vVExvRpr3FuF3cTULKh1B_VSRBp-FveEtq5-KwpFeLESB2KEtJVIt5Czsl_UV1m-AzAzLfHk-RHe-xFSA6cgRQIStlwUe1m1ctm-eRuIt5VMsl7MKcSD-F51BE4CC-iRd-el1UfoEFKZd_edebnBwgBcv332_MLAkEV7VPsIdSwqQn2Mv_F3p-M35-MeWKss17dR-Ege6d_IM442tow7X-35MsiqyNA14xPJB2NoX9996ej383EJKQ9y";
    const string preHex =
        "02010000016c384668747470733a2f2f6d2e70696e64756f64756f2e6e65742f676f6f64732e68746d6c3f676f6f64735f69643d38373932383437303436383026706167655f736e3d3130303134008ba0330740f702bc06481a313136323231383431373036373234392d756e646566696e65645080c249585117974b617969797103786f4d6f7a696c6c612f352e3020284c696e75783b20416e64726f69642031303b204b29204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29204368726f6d652f3134392e302e302e30204d6f62696c65205361666172692f3533372e3336802858706d4a6e30646f6e35544a5830456258435f735f697a646e42666f41666b4e5972657e4c695168882858706d4a6e30646f6e35544a5830456258435f735f697a646e42666f41666b4e5972657e4c695168901868747470733a2f2f6d2e70696e64756f64756f2e6e65742fa901b6019f7cdff8aad014d801e00000";

    var dec = AntiContentCodec.DecodeToken(mockToken);
    string inflHex = Convert.ToHexString(dec.Inflated).ToLowerInvariant();
    Check("decode(mock).inflated == JS pre_deflate (跨语言逐字节)", inflHex == preHex, $"{dec.Inflated.Length}B");

    // PackFields(解析出的字段) 重打包 == pre_deflate
    string repackHex = Convert.ToHexString(AntiContentCodec.Frame(AntiContentCodec.PackFields(dec.Fields))).ToLowerInvariant();
    Check("PackFields(fields) 帧 == pre_deflate (pack 层逐字节)", repackHex == preHex);

    // ReEncode 往返: 解回字节一致
    string re = AntiContentCodec.ReEncode(mockToken);
    var dec2 = AntiContentCodec.DecodeToken(re);
    Check("ReEncode 往返 inflated 一致", Convert.ToHexString(dec2.Inflated) == Convert.ToHexString(dec.Inflated));

    // 字段值校验 (mock)
    string? mockUa = dec.Fields.Find(f => f.Tag == 15)?.Str;
    Check("mock tag15 UA 存在", mockUa != null && mockUa.Contains("Mozilla/5.0"));
    Check("mock tag8 屏幕 375x828", dec.Fields.Find(f => f.Tag == 8) is { Va: { Count: 2 } v } && v[0] == 375 && v[1] == 828);

    // 真机 token (examples/compare/render/real.txt) 解码
    const string realToken =
        "0asWfqnFpioyj9vxknP4PpgU1UWNI1v9oirccirc96Ojg-ny5T-Dv5r76mNgUdsd8KrputvVTBf0TMfUD3NV4PR2vfXUPxN4aVK-wVeFl3a1EnR3xr1zOI-vhv-7kW0KFUYZLPe4_MQdEMqB_sMZpZngUNEV5Pt6Yof84FqANquqXjMnkS_67C1SXikcI12_buBVKpREMV0vZzDtUTf10IynBZeynpd3ABV5Ds1rT_-j3CK31lHBjio6A304FPDvZ7A_KIOLViFpsws1z_wW8coiQS6MqcJxzCSc3udq8rOkaSJaz6qVKWZt8I42t1c6OREWN0eDHt82aeMv1wB6kZY6oI5ueaXTAgF7DB4fX-re6Bx4bay0A-Y3HzbP7KP4yV6jAmZbtZi6bwNxF4pU7CfGZ5qGlAfGtIm_dvV_qPMqhKMwO2gaTtzTARAh2MdUV21g0Um-Ors-Ov4xZoNmNSrvaaZ1FOggRfp0ycgBdcgj1Mlz2zUPMXMtEp5ghkAKRoItP8Wx-GongxQ-InyA2KSYH0oQvQY6MHJLyBHyWXUpoKSHdrmRWLlU5ZwnwzoQIx1-JCHC6kagtzSF3-xnUV8FYKCPMnDIJyKCqqdUi3tUYrcpjydE0Dr5NfD8zbSEd5AkcaXlbclShAsSPA3bEWcIGha833-hrMAHNPaLUwclRRLEyHCqcNH-zdL7NKv-UWFN9d";
    var rdec = AntiContentCodec.DecodeToken(realToken);
    Check("真机 token 解出 19 字段", rdec.Fields.Count == 19, rdec.Fields.Count.ToString());
    Check("真机 tag19 pdd_user_id == 6398454719955", rdec.Fields.Find(f => f.Tag == 19)?.Str == "6398454719955");
    Check("真机 tag15 UA 含 'android ' 前缀", (rdec.Fields.Find(f => f.Tag == 15)?.Str ?? "").StartsWith("android "));
    Check("真机 tag26 浏览器位 == 0 (移动WebView)", rdec.Fields.Find(f => f.Tag == 26) is { Va: { Count: 1 } bv } && bv[0] == 0);
    // 真机 ReEncode 往返
    Check("真机 ReEncode 往返 inflated 一致",
        Convert.ToHexString(AntiContentCodec.DecodeToken(AntiContentCodec.ReEncode(realToken)).Inflated) == Convert.ToHexString(rdec.Inflated));

    // MintFromReal: 刷新时间戳, 保留持久值
    long nowMs = 1799000000123;
    string minted = AntiContentCodec.MintFromReal(realToken, nowMs);
    var mdec = AntiContentCodec.DecodeToken(minted);
    Check("MintFromReal tag22 时间戳已刷新", mdec.Fields.Find(f => f.Tag == 22)?.Num == nowMs);
    Check("MintFromReal tag9 秒时间戳已刷新", (mdec.Fields.Find(f => f.Tag == 9)?.Str ?? "").EndsWith("-" + (nowMs / 1000)));
    Check("MintFromReal 保留真机 pdd_user_id", mdec.Fields.Find(f => f.Tag == 19)?.Str == "6398454719955");
    Check("MintFromReal 保留真机 nano_fp(tag16)", mdec.Fields.Find(f => f.Tag == 16)?.Str == rdec.Fields.Find(f => f.Tag == 16)?.Str);

    // 确定字段对齐: 覆盖 UA(tag15) + 屏幕(tag8) + pdd_user_id(tag19)
    const string mockUaOverride = "android Mozilla/5.0 (Linux; Android 14; MockModel Build/UP1A.999; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/143.0.7499.192 Safari/537.36  phh_android_version/8.8.0 pversion/0";
    string minted2 = AntiContentCodec.MintFromReal(realToken, nowMs, pddUserId: "9999888877776", ua: mockUaOverride, screenAvailW: 393, screenAvailH: 851);
    var m2 = AntiContentCodec.DecodeToken(minted2);
    Check("对齐 tag15 UA == mock UA", m2.Fields.Find(f => f.Tag == 15)?.Str == mockUaOverride);
    Check("对齐 tag8 屏幕 == 393x851", m2.Fields.Find(f => f.Tag == 8) is { Va: { Count: 2 } sv } && sv[0] == 393 && sv[1] == 851);
    Check("对齐 tag19 pdd_user_id == 9999888877776", m2.Fields.Find(f => f.Tag == 19)?.Str == "9999888877776");
    Check("对齐后保留真机 nano_fp(tag16)", m2.Fields.Find(f => f.Tag == 16)?.Str == rdec.Fields.Find(f => f.Tag == 16)?.Str);

    // tag20 (api_uid) 对齐
    const string mockApiUid = "CiYxB2pZfh59dwElGBfqAg==";
    string minted3 = AntiContentCodec.MintFromReal(realToken, nowMs, apiUid: mockApiUid);
    var m3 = AntiContentCodec.DecodeToken(minted3);
    Check("对齐 tag20 api_uid == mock", m3.Fields.Find(f => f.Tag == 20)?.Str == mockApiUid);
    Check("tag20 未传时保留真机值", AntiContentCodec.DecodeToken(AntiContentCodec.MintFromReal(realToken, nowMs)).Fields.Find(f => f.Tag == 20)?.Str == rdec.Fields.Find(f => f.Tag == 20)?.Str);

    // tag23 (pdd_vds) 对齐
    const string mockPddVds = "gaLUNJajOVLFIStkiUnVEVnUmkyXLRoXQjPUtKmJIXtAPUiVmJyHiVISQgOV";
    var m4 = AntiContentCodec.DecodeToken(AntiContentCodec.MintFromReal(realToken, nowMs, pddVds: mockPddVds));
    Check("对齐 tag23 pdd_vds == mock", m4.Fields.Find(f => f.Tag == 23)?.Str == mockPddVds);
    Check("tag23 未传时保留真机值", AntiContentCodec.DecodeToken(AntiContentCodec.MintFromReal(realToken, nowMs)).Fields.Find(f => f.Tag == 23)?.Str == rdec.Fields.Find(f => f.Tag == 23)?.Str);

    // nano_fp (tag16/17) 生成 + 对齐
    string fp = AntiContentCodec.GenNanoFp();
    Check("GenNanoFp 长度 40 + XpmJn0 前缀", fp.Length == 40 && fp.StartsWith("XpmJn0"), fp);
    Check("GenNanoFp pos18 = '_' 分隔符", fp[18] == '_', fp);
    Check("GenNanoFp 前18位无下划线", !fp.Substring(0, 18).Contains('_'));
    Check("GenNanoFp 字符全在字母表", fp.All(c => AntiContentCodec.NanoFpAlphabet.Contains(c)));
    Check("GenNanoFp 两次不同 (随机)", AntiContentCodec.GenNanoFp() != AntiContentCodec.GenNanoFp());
    var m5 = AntiContentCodec.DecodeToken(AntiContentCodec.MintFromReal(realToken, nowMs, nanoFp: fp));
    Check("对齐 tag16 nano_cookie_fp == fp", m5.Fields.Find(f => f.Tag == 16)?.Str == fp);
    Check("对齐 tag17 nano_storage_fp == fp (同值)", m5.Fields.Find(f => f.Tag == 17)?.Str == fp);
    Check("nanoFp 未传时保留真机值", AntiContentCodec.DecodeToken(AntiContentCodec.MintFromReal(realToken, nowMs)).Fields.Find(f => f.Tag == 16)?.Str == rdec.Fields.Find(f => f.Tag == 16)?.Str);
}

Console.WriteLine($"\n==== 汇总: PASS={pass}  FAIL={fail} ====");
return fail == 0 ? 0 : 1;
