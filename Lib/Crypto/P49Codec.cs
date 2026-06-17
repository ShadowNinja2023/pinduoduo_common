using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// p49 生成/随机化实现 — 逆向自 libpdd_secure.so (sub_7B828 组装 + sub_18DAF4 RC4)
    ///
    /// 公式:
    ///   p49 = Base64_std( RC4_standard( CSV, key="a70QuMy3yzd3rv4b" ) )
    ///   CSV = 88 个系统文件 stat().st_ino 逗号拼接, 每段后都有 ','(含末尾), 文件不存在则该段留空。
    ///
    /// - p49 本质 = 文件系统 inode 指纹 (ROM 布局 + 系统包存在性探测), 不含 android_id/oaid。
    /// - 大部分 inode 跟 ROM 镜像绑定 (只读分区/虚拟fs), 同型号设备一致;
    ///   少部分跟运行时可写文件/sdcard/procfs 绑定, 真实设备间会不同。
    ///
    /// mock 策略 (RandomizeFromBaseline):
    ///   解密样本基线 CSV → 只对"真实设备间会变化"的索引 (可写 db/xml、sdcard、usagestats、proc/*、
    ///   webview relro) 做同量级扰动, 只读/结构性 inode 保留 → 重新 RC4+base64。
    ///   这样既让不同 mock 设备的 p49 各异 (避免指纹撞车), 又保持值的合理性。
    ///   完整路径↔索引对照见 docs/04_device_register/08_p49_paths.md。
    /// </summary>
    public static class P49Codec
    {
        /// <summary>p49 专用 RC4 key (硬编码, key表@0x7188ca6360)</summary>
        public static readonly byte[] Rc4Key = Encoding.ASCII.GetBytes("a70QuMy3yzd3rv4b");

        /// <summary>
        /// CSV 中"真实设备间会变化"的字段索引 (0-based, 对照 08_p49_paths.md 的 88 路径顺序):
        ///   39 webview relro / 45 device_policies.xml / 46 entropy.dat / 48 install_sessions /
        ///   49 job / 50 last-fstrim / 51 locksettings.db / 52 netstats / 53 procstats / 54 sync /
        ///   58 userlist.xml / 60-64 sdcard(Android/data/.nomedia/DCIM/Download) / 67 usagestats /
        ///   85 /proc/self / 86 /proc/mounts / 87 /proc/net
        /// 其余 (只读 /system、虚拟 /sys、结构性 /data 低号 inode) 同 ROM 一致, 保留基线。
        /// </summary>
        public static readonly int[] VariableIndices =
        {
            39, 45, 46, 48, 49, 50, 51, 52, 53, 54, 58,
            60, 61, 62, 63, 64, 67, 85, 86, 87
        };

        public static string DecryptToCsv(string base64, byte[]? key = null)
        {
            byte[] pt = P30Codec.Rc4(key ?? Rc4Key, Convert.FromBase64String(base64));
            return Encoding.ASCII.GetString(pt);
        }

        public static string EncryptCsv(string csv, byte[]? key = null)
        {
            byte[] ct = P30Codec.Rc4(key ?? Rc4Key, Encoding.ASCII.GetBytes(csv));
            return Convert.ToBase64String(ct);
        }

        /// <summary>
        /// 由样本基线 p49 (base64) 产出随机化的 p49: 仅扰动 VariableIndices 指向的 inode,
        /// 其余保留。空段保持空。返回新的 base64。
        /// </summary>
        public static string RandomizeFromBaseline(string baselineBase64, byte[]? key = null)
        {
            string csv = DecryptToCsv(baselineBase64, key);
            string[] parts = csv.Split(',');
            var varSet = new HashSet<int>(VariableIndices);

            for (int i = 0; i < parts.Length; i++)
            {
                if (!varSet.Contains(i)) continue;       // 非可变索引保留
                if (parts[i].Length == 0) continue;       // 空段保持空 (文件本就不存在)
                if (!long.TryParse(parts[i], out long v)) continue;
                parts[i] = PerturbInode(v).ToString();
            }
            return EncryptCsv(string.Join(",", parts), key);
        }

        /// <summary>同量级扰动一个 inode: ×[0.65,1.35], 保持正整数且不为 0。</summary>
        private static long PerturbInode(long v)
        {
            double f = 0.65 + RandomNumberGenerator.GetInt32(0, 701) / 1000.0; // 0.65~1.35
            long nv = (long)(v * f);
            if (nv < 1) nv = 1;
            return nv;
        }
    }
}
