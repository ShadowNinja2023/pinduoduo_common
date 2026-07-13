namespace PddLib.Crypto.Extra;

/// <summary>
/// 硬编码 KeyTable (在 libdyncommon.so .data 段, 文件偏移 0x470e48)。
/// KEY_8B = word0 || word1, 每个 word 由一组索引 (i0,i1,i2) 查表得到:
///   table(i0,i1,i2) = LE u32 @ 0x470e48 + i0*0x4000 + i1*0x400 + i2*4
///   KEY_8B = BE(word0) || BE(word1)
/// 索引来源: 每进程随机 (arc4random/lrand48), 并随容器传给服务端 (格式 00||i0||i1||i2)。
/// 因此拿到任意真机 extra 容器里的两组索引, 就能离线查出该设备的 KEY_8B。
/// </summary>
public sealed class KeyTable
{
    private const long FileBase = 0x46f000;   // region 文件起始偏移
    private const long KtOffset = 0x470e48;   // KeyTable 文件偏移
    private readonly byte[] _region;

    public KeyTable(byte[] regionBin) => _region = regionBin;

    public static KeyTable LoadFromFile(string path) => new(File.ReadAllBytes(path));

    /// <summary>从默认数据目录加载 (Data/Extra1008/keytable_region.bin)。</summary>
    public static KeyTable LoadDefault() => LoadFromFile(Path.Combine(Extra1008Data.DefaultDir, "keytable_region.bin"));

    /// <summary>查表得一个 32 位 word (小端存储)。</summary>
    public uint Word(int i0, int i1, int i2)
    {
        long off = KtOffset + (long)i0 * 0x4000 + (long)i1 * 0x400 + (long)i2 * 4 - FileBase;
        if (off < 0 || off + 4 > _region.Length)
            throw new ArgumentOutOfRangeException($"索引 ({i0},{i1},{i2}) 超出 region 范围");
        return BitConverter.ToUInt32(_region, (int)off); // 小端
    }

    /// <summary>由两组索引拼出 8 字节 KEY_8B = BE(word0) || BE(word1)。</summary>
    public byte[] DeriveKey8(Index3 word0Idx, Index3 word1Idx)
    {
        var key = new byte[8];
        WriteBE(key, 0, Word(word0Idx.I0, word0Idx.I1, word0Idx.I2));
        WriteBE(key, 4, Word(word1Idx.I0, word1Idx.I1, word1Idx.I2));
        return key;
    }

    private static void WriteBE(byte[] buf, int off, uint v)
    {
        buf[off + 0] = (byte)(v >> 24);
        buf[off + 1] = (byte)(v >> 16);
        buf[off + 2] = (byte)(v >> 8);
        buf[off + 3] = (byte)v;
    }
}

/// <summary>KeyTable 三级索引 (i0∈[0,8], i1∈[0,15], i2∈[0,255])。容器里编码为 00||i0||i1||i2。</summary>
public readonly record struct Index3(int I0, int I1, int I2)
{
    /// <summary>从容器里的 4 字节标记 00||i0||i1||i2 解析。</summary>
    public static Index3 FromMarker(ReadOnlySpan<byte> marker4)
        => new(marker4[1], marker4[2], marker4[3]);

    public override string ToString() => $"({I0},{I1},{I2})";
}
