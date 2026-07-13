using System;
using PddLib.Register;

namespace PddLib.Crypto
{
    /// <summary>
    /// 从 DeviceProfile 构造 info2 (2af anti-token) 的完整 34 字段 TLV, 并生成 anti-token 头。
    ///
    /// 字段编码见 docs/04_device_register/14_info2_antitoken_analysis.md。
    /// per-台唯一/运行时值:
    ///   idx1e = android_id(8B), idx20 = currentTime(ms), idx21 = 8B 纯随机, idx22 = 随机 GUID(去-)。
    /// </summary>
    public static class Info2Builder
    {
        /// <summary>构造 info2 TLV 明文帧 (34 字段)。</summary>
        /// <param name="d">设备</param>
        /// <param name="currentTimeMs">idx20 currentTime; null 取当前墙钟 ms</param>
        public static byte[] BuildTlv(DeviceProfile d, long? currentTimeMs = null)
        {
            long nowMs = currentTimeMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var t = new Info2Tlv()
                .PutString(0x01, d.Sno)                     // sno 序列号
                .PutString(0x02, d.Brand)                   // Build.BRAND
                .PutString(0x03, d.Device)                  // Build.DEVICE
                .PutString(0x04, d.Model)                   // Build.MODEL
                .PutString(0x05, d.Manufacturer)            // Build.MANUFACTURER
                .PutString(0x06, d.Board)                   // Build.BOARD
                .PutString(0x07, d.Display)                 // Build.DISPLAY
                // idx08: Build.ID/Build.DISPLAY:type/tags (≠ meta_info 的 Build.FINGERPRINT)
                .PutString(0x08, $"{d.BuildId}/{d.Display}:user/release-keys")
                .PutString(0x09, d.Osv)                     // Build.VERSION.RELEASE
                .PutU8    (0x0a, d.SdkInt)                  // Build.VERSION.SDK_INT
                .PutU32   (0x0b, d.BuildDateUtc)            // ro.build.date.utc
                .PutU32   (0x0c, d.BuildPropTimeUtc)        // /system/build.prop mtime
                .PutEmpty (0x0d).PutEmpty(0x0e).PutEmpty(0x0f).PutEmpty(0x10).PutEmpty(0x11) // 保留
                .PutU8    (0x12, d.SimState)                // getSimState
                .PutString(0x13, d.SimOperatorName)         // getSimOperatorName
                .PutString(0x14, d.SimCountryIso)           // getSimCountryIso (可 "cn")
                .PutEmpty (0x15)                            // 保留/待确认
                .PutString(0x16, d.NetworkType)             // getNetworkType (UNKNOWN/LTE...)
                .PutString(0x17, d.NetworkMcc)              // getNetworkOperator[:3]
                .PutString(0x18, d.NetworkMnc)              // getNetworkOperator[3:]
                .PutString(0x19, d.NetworkOperatorName)     // getNetworkOperatorName
                .PutString(0x1a, d.NetworkCountryIso)       // getNetworkCountryIso (可 "cn")
                .PutU8    (0x1b, d.DataState)               // getDataState
                .PutU8    (0x1c, d.DataActivity)            // getDataActivity
                .PutRaw   (0x1d, d.Info2KernelValue)        // kernel /proc/version 复合 (基线)
                .PutBytes (0x1e, HexToBytes(d.AndroidId))   // android_id (8B)
                .PutU8    (0x1f, 0)                         // 保留 (样本恒 0)
                .PutU64   (0x20, nowMs)                     // currentTime ms
                .PutBytes (0x21, RandomBytes(8))            // PRNG 随机 8B (服务端不还原)
                .PutString(0x22, RandomGuidNoDash());       // 随机 GUID 去 "-"

            return t.Build();
        }

        /// <summary>构造 anti-token 头 (含 "2af" 前缀)。</summary>
        public static string BuildAntiToken(DeviceProfile d, long? currentTimeMs = null)
            => Info2Codec.Encrypt(BuildTlv(d, currentTimeMs));

        // ==================== helpers ====================

        private static byte[] HexToBytes(string hex)
        {
            hex ??= "";
            var b = new byte[hex.Length / 2];
            for (int i = 0; i < b.Length; i++)
                b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        private static byte[] RandomBytes(int n)
        {
            var b = new byte[n];
            System.Security.Cryptography.RandomNumberGenerator.Fill(b);
            return b;
        }

        private static string RandomGuidNoDash() => Guid.NewGuid().ToString("N");
    }
}
