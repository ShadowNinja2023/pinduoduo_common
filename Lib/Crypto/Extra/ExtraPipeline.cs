using System.Text.Json;
using PddLib.Crypto;

namespace PddLib.Crypto.Extra;

/// <summary>
/// 全链路串联: user_env2 外层(TEA-CBC) ↔ 内层 extra(1008 容器)。
///
/// 解密方向: user_env2 blob → UserEnv2Codec 解 TEA-CBC → 取 JSON 的 "extra" 字段
///           → 去 "01" 文本前缀 → base64 解码 → 1008 容器 → Extra1008Codec.DecryptByLenflag。
/// 编码方向: 1008 容器 → "01"+base64 → 作为 UserEnv2Codec.Form06 的 extra 字段 → TEA-CBC → user_env2 blob。
/// </summary>
public static class ExtraPipeline
{
    /// <summary>从 user_env2 外层 blob 解出内层 extra 容器字节。</summary>
    public static byte[] ExtractContainer(string userEnv2Blob, byte[]? key = null)
    {
        string json = UserEnv2Codec.Decrypt(userEnv2Blob, key);
        return ExtractContainerFromPlaintext(json);
    }

    /// <summary>从 user_env2 明文 JSON 取 extra 字段并解码为 1008 容器字节。</summary>
    public static byte[] ExtractContainerFromPlaintext(string userEnv2Json)
    {
        using var doc = JsonDocument.Parse(userEnv2Json);
        if (!doc.RootElement.TryGetProperty("extra", out var ex))
            throw new InvalidOperationException("user_env2 明文无 extra 字段");
        string s = ex.GetString() ?? "";
        if (s.Length == 0) throw new InvalidOperationException("extra 字段为空");
        if (s.StartsWith("01")) s = s[2..];   // 去文本前缀 "01"
        return B64Decode(s);
    }

    /// <summary>1008 容器字节 → extra 字段值 ("01" 前缀 + 标准 base64, 去 '=' 填充)。</summary>
    public static string ToExtraField(byte[] container)
        => "01" + Convert.ToBase64String(container).TrimEnd('=');

    private static byte[] B64Decode(string s)
    {
        int m = s.Length % 4;
        if (m != 0) s += new string('=', 4 - m);
        return Convert.FromBase64String(s);
    }
}
