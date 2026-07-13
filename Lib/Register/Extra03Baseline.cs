namespace PddLib.Register
{
    /// <summary>
    /// 03 报文 (extra/data_type=20, SE.us 安全检测) 内层字段基线常量。
    /// 取自干净环境真机 us() live 解密 (device_report_example/decrypted/03_inner_clean_live.json)。
    ///
    /// 说明:
    /// - 内层 JSON 所有字段值都是"字符串"(含 emulator_detect/dedez 这种字符串化的 JSON)。
    /// - 当前真机在服务端 AB 关闭时, 不发 8f70d/5b766/y5dx/zt12t/zddgq 这组深度采集字段
    ///   (见 docs/04_device_register/10_request03_extra_analysis.md 第九节), 故 mock 也不放。
    /// - rootInfo/frida_detect 等均为"干净环境"结果, 复刻即上报一台无 hook/无 root 的设备。
    /// ★ 2026-07 按 docs 16 §1.3/§6 全面去 frida 污染 (旧基线取自 frida hook 环境):
    ///   rootInfo 0→-1/seg2 (null)、pts 空、去 oem_unlock_supported、emulator_detect 去 5/13。
    /// </summary>
    public static class Extra03Baseline
    {
        public const string Dynver = "1.1.3";
        public const string Parallel = "0|0|0|0";
        /// <summary>★ 真·干净值 (docs 16 §1.3/§6): seg0=-1(未命中), seg2=(null)。
        /// 旧值 0|(null)||…|0 是 frida 环境污染 (seg0=0=被干预)。格式: flag|(null)|(null)|全零base64|0。</summary>
        public const string RootInfoClean = "-1|(null)|(null)|AAAAAAAAAAAAAAAAAAAAAAAAAAA=|0";
        public const string OemUnlockStatus = "0";
        public const string VerifiedBootState = "green";
        public const string CpuAbi = "arm64-v8a";
        public const string WifiAdbEnabled = "0";
        /// <summary>★ 干净值 (docs 16 §1.3/§6): 空串。旧的 devpts 项非空是 frida-server 占用 pts 的痕迹。</summary>
        public const string Pts = "";
        public const string AppProcAccessSize = "-rwxr-xr-x|51776|4744";
        public const string FramworkAccessSize = "-rw-r--r--|44995090|0";
        public const string FridaDetect = "{}";
        public const string DebugDetect = "{}";
        public const string RepackDetect = "{}";
        public const string SeccompDetect = "{}";
        /// <summary>★ 干净值 (docs 16 §1.3/§6): 去掉 frida 痕迹项 "5":"0" 与 "13":"debugfs"。字符串化 JSON。</summary>
        public const string EmulatorDetect = "{\"3\":\"\",\"7\":\"unknown\",\"17\":\"88\"}";
        public const string HookDetect = "{}";
        public const string SepolicyHash = "0|e5eefc9504dcd1ebd119b60d0fdf55da2fe11203f338db8e0c9a0efd5d9c83b5";
        public const string Dedez = "{\"5\":\"google|pixel\",\"6\":\"\"}";
    }
}
