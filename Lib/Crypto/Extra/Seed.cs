namespace PddLib.Crypto.Extra;

/// <summary>
/// keystream 种子: 16 字节 = 4279(marker) | nonce(4) | counter(2) | KEY_8B(8)。
/// keystream = G(seed)，G 由具体的 IKeystreamGenerator 实现。
/// </summary>
public static class Seed
{
    public const int Length = 16;

    /// <summary>用 nonce/counter/KEY_8B 组装 16 字节 seed。</summary>
    public static byte[] Build(byte[] nonce4, byte[] counter2, byte[] key8)
    {
        if (nonce4.Length != 4) throw new ArgumentException("nonce 必须 4 字节", nameof(nonce4));
        if (counter2.Length != 2) throw new ArgumentException("counter 必须 2 字节", nameof(counter2));
        if (key8.Length != 8) throw new ArgumentException("KEY_8B 必须 8 字节", nameof(key8));

        var seed = new byte[Length];
        seed[0] = 0x42; seed[1] = 0x79;          // 固定 marker
        Array.Copy(nonce4, 0, seed, 2, 4);       // [2:6]  nonce
        Array.Copy(counter2, 0, seed, 6, 2);     // [6:8]  counter
        Array.Copy(key8, 0, seed, 8, 8);         // [8:16] KEY_8B
        return seed;
    }

    public static byte[] FromHex(string hex)
    {
        hex = hex.Replace(" ", "").Replace("\n", "").Trim();
        var b = new byte[hex.Length / 2];
        for (int i = 0; i < b.Length; i++)
            b[i] = Convert.ToByte(hex.Substring(2 * i, 2), 16);
        return b;
    }

    public static string ToHex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
}
