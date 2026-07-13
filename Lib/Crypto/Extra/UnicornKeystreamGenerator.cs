using PddLib.Crypto.Extra.Native;

namespace PddLib.Crypto.Extra;

/// <summary>
/// 用 Unicorn2 执行 libdyncommon 的真实 G 代码, 从快照现场恢复 → 覆写 seed → 生成 keystream。
/// 跟随真实控制流, 对任意 nonce/KEY 全块正确 (含 block2+ 的数据相关派发)。
///
/// 引擎复用: uc_open + 映射只做一次; 每次 Generate 前恢复被改动的内存 + 重置寄存器 + 覆写 seed。
/// QEMU 的 TB 翻译缓存跨调用复用, 显著快于每次重建引擎。非线程安全 (每线程一个实例)。
///
/// 采用「无回调」设计 (回调进 .NET 托管代码 + Unicorn JIT 易出问题): 用 emu_start 的 until
/// 停在 keystream 就绪点 (0x34d90c) 抓每块; 取指未映射用重试循环补 RET。
///
/// 块数上限突破: 快照默认输出长度预算 656B(=41块) 存于栈 SP+0xe0(值 655=长度-1);
/// 每次生成前 patch 放大, 即可生成任意长 keystream (前 41 块与原始逐字节一致, 已回归)。
///
/// 依赖: Data/Extra1008/ 下 meta.json + so.bin + stack.bin (unidbg 在 0x3516c8 dump), 以及 unicorn.dll。
/// 注意: 宿主 exe 需关 CFG (post-build 清 apphost GUARD_CF) + CET(&lt;CETCompat&gt;false), 否则 Unicorn JIT 会 fastfail。
/// </summary>
public sealed class UnicornKeystreamGenerator : IKeystreamGenerator, IDisposable
{
    private const int KS_DUMP_OFF = 0x34d90c;   // keystream 就绪点 (XOR 消费循环内)
    private const int STAGING_OFF = 0x210;      // staging = sp + 0x210, 每 seed 字节步长 4
    private const int STATE_OFF   = 0x400;      // 状态/keystream 缓冲 = sp + 0x400
    private const int LENBUDGET_OFF = 0xe0;     // 输出长度预算(字节-1), 快照原始=655=41块×16-1
                                                // patch 放大即可突破 41 块上限, 生成任意长 keystream

    private static readonly byte[] Ret = { 0xC0, 0x03, 0x5F, 0xD6 };

    private readonly Snapshot _snap;
    private IntPtr _uc;
    private bool _engineReady;
    private bool _disposed;

    /// <summary>是否每次生成前恢复整块 .so 映像 (稳妥, 略慢)。若 G 不写 .so 数据段可设 false 提速。</summary>
    public bool RestoreSoEachCall { get; set; } = false;
    public bool Verbose { get; set; }

    /// <summary>从指定数据目录加载快照。</summary>
    public UnicornKeystreamGenerator(string dataDir) => _snap = Snapshot.Load(dataDir);

    /// <summary>从默认数据目录 (Data/Extra1008/) 加载快照。</summary>
    public UnicornKeystreamGenerator() : this(Extra1008Data.DefaultDir) { }

    private void EnsureEngine()
    {
        if (_engineReady) return;
        Uc.Check(Uc.uc_open(Uc.UC_ARCH_ARM64, Uc.UC_MODE_ARM, out _uc), "uc_open");
        // 映射 .so + 栈 + G 只读的零页 (只做一次)
        MapAndWrite(_uc, _snap.SoBase, _snap.SoImage);
        MapAndWrite(_uc, _snap.StackBase, _snap.StackImage);
        MapZero(_uc, 0x0, 0x10000);
        MapZero(_uc, (_snap.SoBase - 0x80000) & ~0xFFFUL, 0x80000);
        MapZero(_uc, 0x14000000, 0x1000000);
        _engineReady = true;
    }

    public byte[] Generate(byte[] seed16, int nBytes)
    {
        if (_disposed) throw new ObjectDisposedException(nameof(UnicornKeystreamGenerator));
        if (seed16.Length != 16) throw new ArgumentException("seed 必须 16 字节");
        int nBlocks = (nBytes + 15) / 16;
        EnsureEngine();

        // --- 每次调用前: 恢复被改动的内存 (栈必恢复; .so 视情况) + 重置寄存器 ---
        Uc.uc_mem_write(_uc, _snap.StackBase, _snap.StackImage, (UIntPtr)_snap.StackImage.Length);
        if (RestoreSoEachCall)
            Uc.uc_mem_write(_uc, _snap.SoBase, _snap.SoImage, (UIntPtr)_snap.SoImage.Length);

        for (int k = 0; k <= 28; k++) WriteReg(_uc, Uc.REG_X0 + k, _snap.Regs[$"x{k}"]);
        WriteReg(_uc, Uc.REG_X29, _snap.Regs["fp"]);
        WriteReg(_uc, Uc.REG_X30, _snap.Regs["lr"]);
        WriteReg(_uc, Uc.REG_SP, _snap.Sp);
        WriteReg(_uc, Uc.REG_NZCV, _snap.Nzcv);
        WriteReg(_uc, Uc.REG_PC, _snap.Pc);

        // 覆写 staging = 目标 seed
        ulong staging = _snap.Sp + STAGING_OFF;
        for (int k = 0; k < 16; k++)
            Uc.uc_mem_write(_uc, staging + (ulong)(4 * k), new[] { seed16[k] }, (UIntPtr)1);

        // 放大输出长度预算, 让消费循环持续生成足够块 (突破快照默认的 41 块上限)
        uint budget = (uint)Math.Max(0x2000, nBlocks * 16 + 64);
        Uc.uc_mem_write(_uc, _snap.Sp + LENBUDGET_OFF, BitConverter.GetBytes(budget), (UIntPtr)4);

        // 无回调抓块: emu_start(until=DUMP) 停在 keystream 就绪点
        ulong dump = _snap.SoBase + KS_DUMP_OFF;
        ulong stateAddr = _snap.Sp + STATE_OFF;
        var blocks = new List<byte[]>();
        byte[]? last = null;
        ulong pc = _snap.Pc;
        int guard = 0;

        while (blocks.Count < nBlocks && guard++ < 2_000_000)
        {
            int err = Uc.uc_emu_start(_uc, pc, dump, 0, UIntPtr.Zero);
            ulong now = 0; Uc.uc_reg_read(_uc, Uc.REG_PC, ref now);

            if (err != 0)
            {
                ulong pg = now & ~0xFFFUL;
                if (Uc.uc_mem_map(_uc, pg, (UIntPtr)0x1000, Uc.UC_PROT_ALL) == 0)
                {
                    Uc.uc_mem_write(_uc, now, Ret, (UIntPtr)4);
                    pc = now; continue;
                }
                throw new InvalidOperationException($"emu 失败: {Uc.StrError(err)} @0x{now:x}");
            }
            if (now != dump) break;

            var buf = new byte[16];
            Uc.uc_mem_read(_uc, stateAddr, buf, (UIntPtr)16);
            if (last == null || !buf.AsSpan().SequenceEqual(last))
            {
                last = buf; blocks.Add(buf);
                if (Verbose) Console.Error.WriteLine($"    [uc] block{blocks.Count - 1} = {Convert.ToHexString(buf).ToLowerInvariant()}");
                if (blocks.Count >= nBlocks) break;
            }
            Uc.uc_emu_start(_uc, dump, 0, 0, (UIntPtr)1);
            Uc.uc_reg_read(_uc, Uc.REG_PC, ref pc);
        }

        if (blocks.Count < nBlocks)
            throw new InvalidOperationException($"只抓到 {blocks.Count} 块, 需要 {nBlocks} 块");

        var ks = new byte[nBlocks * 16];
        for (int i = 0; i < nBlocks; i++) Array.Copy(blocks[i], 0, ks, i * 16, 16);
        return ks[..nBytes];
    }

    private static void MapAndWrite(IntPtr uc, ulong baseAddr, byte[] data)
    {
        ulong size = (ulong)((data.Length + 0xFFF) & ~0xFFF);
        Uc.Check(Uc.uc_mem_map(uc, baseAddr, (UIntPtr)size, Uc.UC_PROT_ALL), $"map 0x{baseAddr:x}");
        Uc.Check(Uc.uc_mem_write(uc, baseAddr, data, (UIntPtr)data.Length), $"write 0x{baseAddr:x}");
    }

    private static void MapZero(IntPtr uc, ulong baseAddr, ulong size)
        => Uc.uc_mem_map(uc, baseAddr, (UIntPtr)size, Uc.UC_PROT_ALL); // 已映射/重叠则忽略

    private static void WriteReg(IntPtr uc, int id, ulong val) => Uc.uc_reg_write(uc, id, ref val);

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_engineReady && _uc != IntPtr.Zero) Uc.uc_close(_uc);
        _uc = IntPtr.Zero;
    }
}
