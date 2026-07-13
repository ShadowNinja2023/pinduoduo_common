namespace PddLib.Crypto.Extra;

/// <summary>
/// extra(1008) 依赖的数据文件目录 (KeyTable region + unidbg 快照 meta.json/so.bin/stack.bin)。
/// 随程序集输出到 Data/Extra1008/ (见 PddLib.csproj)。
/// </summary>
public static class Extra1008Data
{
    /// <summary>默认数据目录 = 可执行输出目录下的 Data/Extra1008/。可用 Override 改。</summary>
    public static string DefaultDir { get; set; } = Path.Combine(AppContext.BaseDirectory, "Data", "Extra1008");
}
