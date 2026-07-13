using System.Runtime.InteropServices;

namespace PddLib.Crypto.Extra.Native;

/// <summary>
/// Unicorn2 C API 的最小 P/Invoke 封装 (直连 unicorn.dll)。
/// 只声明本项目用到的函数, 避免依赖第三方 .NET 绑定包。
/// 运行时需要 unicorn.dll (Unicorn2, win-x64) 在可执行目录下。
/// </summary>
public static class Uc
{
    const string DLL = "unicorn";

    // 注册 DllImport 解析器: 在多个候选路径找 unicorn.dll (输出根 / Native / Data/Extra1008)。
    // 静态构造在首次 P/Invoke 前运行, 无需把 dll 放在 exe 根目录。
    static Uc()
    {
        System.Runtime.InteropServices.NativeLibrary.SetDllImportResolver(typeof(Uc).Assembly, (name, asm, path) =>
        {
            if (!name.StartsWith("unicorn", StringComparison.OrdinalIgnoreCase)) return IntPtr.Zero;
            foreach (var cand in new[]
            {
                Path.Combine(AppContext.BaseDirectory, "unicorn.dll"),
                Path.Combine(AppContext.BaseDirectory, "Native", "unicorn.dll"),
                Path.Combine(Extra1008Data.DefaultDir, "unicorn.dll"),
            })
            {
                if (File.Exists(cand) && System.Runtime.InteropServices.NativeLibrary.TryLoad(cand, out var h)) return h;
            }
            return IntPtr.Zero; // 交回默认解析 (可能抛 DllNotFoundException)
        });
    }

    // arch / mode
    public const uint UC_ARCH_ARM64 = 2;
    public const uint UC_MODE_ARM = 0;      // arm64 = little-endian, mode 0

    // perms
    public const uint UC_PROT_ALL = 7;

    // hook types
    public const int UC_HOOK_CODE = 4;
    public const int UC_HOOK_MEM_READ_UNMAPPED = 16;
    public const int UC_HOOK_MEM_WRITE_UNMAPPED = 32;
    public const int UC_HOOK_MEM_FETCH_UNMAPPED = 64;
    public const int UC_HOOK_MEM_UNMAPPED =
        UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED; // 112

    // uc_mem_type
    public const int UC_MEM_FETCH_UNMAPPED = 21;

    // arm64 register ids (来自 unicorn arm64_const)
    public const int REG_X29 = 1, REG_X30 = 2, REG_NZCV = 3, REG_SP = 4;
    public const int REG_X0 = 199;   // X0..X28 = 199..227
    public const int REG_PC = 260;

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void CodeHookCb(IntPtr uc, ulong address, uint size, IntPtr user);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    [return: MarshalAs(UnmanagedType.I1)]
    public delegate bool MemHookCb(IntPtr uc, int type, ulong address, int size, long value, IntPtr user);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_open(uint arch, uint mode, out IntPtr uc);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_close(IntPtr uc);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_mem_map(IntPtr uc, ulong address, UIntPtr size, uint perms);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_mem_write(IntPtr uc, ulong address, byte[] bytes, UIntPtr size);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_mem_read(IntPtr uc, ulong address, byte[] bytes, UIntPtr size);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_reg_write(IntPtr uc, int regid, ref ulong value);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_reg_read(IntPtr uc, int regid, ref ulong value);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_emu_start(IntPtr uc, ulong begin, ulong until, ulong timeout, UIntPtr count);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_emu_stop(IntPtr uc);

    // 变参 C 函数; UC_HOOK_CODE / UC_HOOK_MEM_* 只用到 begin,end, 固定声明即可
    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int uc_hook_add(IntPtr uc, out IntPtr hh, int type, IntPtr callback,
        IntPtr user, ulong begin, ulong end);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr uc_strerror(int err);

    public static string StrError(int err)
    {
        var p = uc_strerror(err);
        return p == IntPtr.Zero ? $"err {err}" : (Marshal.PtrToStringAnsi(p) ?? $"err {err}");
    }

    public static void Check(int err, string what)
    {
        if (err != 0) throw new InvalidOperationException($"{what} 失败: {StrError(err)} ({err})");
    }
}
