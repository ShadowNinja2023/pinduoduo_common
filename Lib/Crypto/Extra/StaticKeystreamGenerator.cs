namespace PddLib.Crypto.Extra;

/// <summary>
/// 演示/测试用 keystream 生成器: 直接返回预先算好的 keystream (来自 unidbg patch-seed dump)。
/// 仅用于跑通/验证上层编解码链路。生产环境请换成 UnicornKeystreamGenerator。
///
/// 可注册多个 (seed -> keystream) 映射; Generate 时按 seed 命中, 未命中抛异常。
/// </summary>
public sealed class StaticKeystreamGenerator : IKeystreamGenerator
{
    private readonly Dictionary<string, byte[]> _table = new();

    /// <summary>登记一条已知 (seed -> keystream)。keystream 需足够长以覆盖需求。</summary>
    public StaticKeystreamGenerator Add(byte[] seed16, byte[] keystream)
    {
        _table[Seed.ToHex(seed16)] = keystream;
        return this;
    }

    public byte[] Generate(byte[] seed16, int nBytes)
    {
        var key = Seed.ToHex(seed16);
        if (!_table.TryGetValue(key, out var ks))
            throw new InvalidOperationException(
                $"StaticKeystreamGenerator 未登记 seed={key} 的 keystream。" +
                "请先用 unidbg/Unicorn 跑出该 seed 的 keystream 并 Add(), 或接入真实生成器。");
        if (ks.Length < nBytes)
            throw new InvalidOperationException(
                $"已登记的 keystream 只有 {ks.Length}B, 需要 {nBytes}B。");
        return ks[..nBytes];
    }
}
