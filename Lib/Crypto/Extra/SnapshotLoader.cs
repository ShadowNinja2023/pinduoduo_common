using System.Text.Json;

namespace PddLib.Crypto.Extra;

/// <summary>解析 unidbg dump 的快照 meta.json + so.bin + stack.bin (供 Unicorn 执行真实 G)。</summary>
public sealed class Snapshot
{
    public ulong SoBase { get; init; }
    public ulong SoSize { get; init; }
    public ulong Pc { get; init; }
    public ulong Sp { get; init; }
    public ulong Nzcv { get; init; }
    public ulong StackBase { get; init; }
    public ulong StackSize { get; init; }
    public required Dictionary<string, ulong> Regs { get; init; }
    public required byte[] SoImage { get; init; }
    public required byte[] StackImage { get; init; }

    public static Snapshot Load(string dir)
    {
        string metaPath = Path.Combine(dir, "meta.json");
        using var doc = JsonDocument.Parse(File.ReadAllBytes(metaPath));
        var root = doc.RootElement;

        ulong H(string k) => ParseHex(root.GetProperty(k).GetString()!);

        var regs = new Dictionary<string, ulong>();
        foreach (var p in root.GetProperty("arm_regs").EnumerateObject())
            regs[p.Name] = ParseHex(p.Value.GetString()!);

        return new Snapshot
        {
            SoBase = H("so_base"),
            SoSize = H("so_size"),
            Pc = H("pc"),
            Sp = H("sp"),
            Nzcv = root.TryGetProperty("nzcv", out var nz) ? ParseHex(nz.GetString()!) : 0,
            StackBase = H("stack_base"),
            StackSize = H("stack_size"),
            Regs = regs,
            SoImage = File.ReadAllBytes(Path.Combine(dir, "so.bin")),
            StackImage = File.ReadAllBytes(Path.Combine(dir, "stack.bin")),
        };
    }

    private static ulong ParseHex(string s)
    {
        s = s.Trim();
        if (s.StartsWith("0x") || s.StartsWith("0X")) s = s[2..];
        return Convert.ToUInt64(s, 16);
    }
}
