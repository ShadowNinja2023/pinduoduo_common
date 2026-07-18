using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PddLib.H5;

string svc = @"F:\TraceWorkspaces\拼多多全量分析\scripts\h5_tools\h5_service.js";
string envPath = @"F:\TraceWorkspaces\拼多多全量分析\scripts\h5_tools\env_real.json";

Console.OutputEncoding = Encoding.UTF8;
Console.WriteLine("启动 H5 服务并预热(约 15-30s)...");
using var h5 = new H5CryptoClient(svc);
await h5.WaitReadyAsync(TimeSpan.FromSeconds(90));
Console.WriteLine("[ready] 预热完成\n");

object? env = JsonSerializer.Deserialize<object>(File.ReadAllText(envPath));

// 1) anti_content
string anti = await h5.GetAntiContentAsync(env);
Console.WriteLine($"[1] anti_content  len={anti.Length}");
Console.WriteLine("    " + anti[..Math.Min(60, anti.Length)] + "...\n");

// 2) csr_risk_token + key/iv
var kic = await h5.GetKeyIvCsrAsync();
Console.WriteLine($"[2] csr_risk_token len={kic.CsrRiskToken.Length}");
Console.WriteLine($"    csr : {kic.CsrRiskToken[..50]}...");
Console.WriteLine($"    key : {kic.RawKey}  (len {kic.RawKey.Length})");
Console.WriteLine($"    iv  : {kic.RawIV}  (len {kic.RawIV.Length})\n");

// 3) AES 往返: C# 用 key/iv 加密 → 服务解密, 验证一致
string plainIn = "{\"goods_id\":879284704680,\"price\":998,\"ok\":true}";
using var aes = Aes.Create();
aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
aes.Key = Encoding.UTF8.GetBytes(kic.RawKey);
aes.IV = Encoding.UTF8.GetBytes(kic.RawIV);
byte[] ct = aes.EncryptCbc(Encoding.UTF8.GetBytes(plainIn), aes.IV, PaddingMode.PKCS7);
string encInfo = Convert.ToBase64String(ct).Replace('+', '-').Replace('/', '_').TrimEnd('=');
string? dec = await h5.DecryptEncryptInfoAsync(encInfo, kic.RawKey, kic.RawIV);
Console.WriteLine($"[3] AES 往返: C# 加密 → 服务解密");
Console.WriteLine($"    原文: {plainIn}");
Console.WriteLine($"    解出: {dec}");
Console.WriteLine($"    一致: {dec == plainIn}");

Console.WriteLine("\n==== 冒烟测试完成 ====");
