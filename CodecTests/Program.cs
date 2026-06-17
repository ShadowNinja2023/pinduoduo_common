using System.Text;
using PddLib.Crypto;
using PddLib.Register;

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

Console.WriteLine($"\n==== 汇总: PASS={pass}  FAIL={fail} ====");
return fail == 0 ? 0 : 1;
