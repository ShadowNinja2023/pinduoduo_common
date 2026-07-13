using System;

namespace PddLib.Register
{
    /// <summary>
    /// data_type=15 报文 es 明文的字段基线 (取自干净流程 report_03, 921B 明文全解, 见 docs 19)。
    ///
    /// es 明文 = 反篡改/环境检测键值集 (18 字段)。检测类字段 (p62 函数序言完整性 / p70·p71 摘要 /
    /// p84·p93·p98 计时记录) 属**环境/so版本相关**, mock 复刻干净基线即可 (与 03 s_f_d 同思路)。
    ///
    /// ★ 明文内加密子blob (p74/p75/p84/p93/p98) = base64( 明文 XOR 逐字段固定keystream )。
    ///   keystream 逐字段固定、跨设备一致 (docs 19 §3), 从 unidbg dump 提取。
    /// ★ 整份 es 无任何非对称签名 (p98 也是 keystream 产物, 非 RSA) → 完全可 mock, 无签名 key 依赖。
    /// </summary>
    public static class Type15Baseline
    {
        // ---- p62: 9 个受监控函数序言完整性 (12B hex 各, 反 inline-hook; 干净未hook基线) ----
        public static readonly string[] P62 =
        {
            "3f2303d5ff8303d1fd7b08a9", // 0
            "3f2303d5ff8306d1fd7b14a9", // 1
            "3f2303d5ff8303d1fd7b08a9", // 2
            "3f2303d5ffc306d1fd7b15a9", // 3
            "3f2303d5ff8303d1fd7b08a9", // 4
            "3f2303d5ff8306d1fd7b14a9", // 5
            "3f2303d5ff4303d1fd7b07a9", // 6
            "3f2303d5ff4306d1fd7b13a9", // 7
            "5f2403d5e22800b43f2303d5", // 8 (bti c; cbz; paciasp)
        };

        // ---- 标量/字符串检测字段 (report_03 干净基线) ----
        public const string P63 = "";
        public const string P64 = "4040";
        public const string P69 = "1";
        public const string P70 = "f41042fb";                                   // 4B hex 摘要
        public const string P71 = "b09f677cd333cef2e771eec9448eeca77cc62879";   // SHA1(20B)
        public const string P73 = "64";
        public const long   P82 = 30290085;                                     // 疑 elapsedRealtime(ms)
        public const long   P83 = 30035968;                                     // 疑 uptimeMillis(ms)
        public const string P94 = "0";
        public const int    P131 = 4;

        // ---- 加密子blob 逐字段固定 keystream (hex) ----
        public static readonly byte[] KsP74 = Hex(
            "1b9478d4cf76acb165d82022f323b54f572e77fc85be0789cd366f10bf5da6acb651cb8ee2770e0aeafe0e5e91593ab6ae8483db99a03c0bf472fbdd348ca7");
        public static readonly byte[] KsP75 = Hex(
            "9c791cc8fa49dcc05f36a2253c44247a4b0acdd34fc2df6d3740f2b8b7d4ddf5f8eaf3648bf629e1786d74e5f0234dd04b89fdbf0115ec00a13ef1ff3094dbf7e32981ec5b07ad31619b627e27efb889ed760dbc8c4e8a7d46afe3e842963a10afcf58146d138bcf5cec19d50b02ba305721d5fb28");
        public static readonly byte[] KsP84 = Hex("7858969d4ed89dd8a2d76c30f1c0ed");
        public static readonly byte[] KsP93 = Hex("65f9b6dabc29ddc5c884749c03f871");
        public static readonly byte[] KsP98 = Hex(
            "012d060d6bfa9a1b3b8dc117057cd4bac64d60f56ae7aa7ee4df12ba90ad04df87b24a1bd88e79f0db9ff7f76de3809d6db36a77d6a3e0fa726ec3b5cc8b6222580f43b8b53501089b1d25b34d281e75640c1519df53d536153f4a2847157230492a77b59e220cd8054103089bc55e5bafd056a71009b9b1d9d8efc987c780f1");

        // ---- 子blob 明文基线 (report_03 干净样本, 用于逐字节复刻) ----
        /// <summary>p74 = 调用方组件工厂类名。</summary>
        public const string P74Plain = "androidx.core.app.CoreComponentFactory";
        /// <summary>p75 = app base.apk 全路径 (Android10+ 含 ~~随机==~~ 段; per-install)。</summary>
        public const string P75Plain =
            "/data/app/~~D4jsoNd_EmEwJ_s8Wz53nQ==/com.xunmeng.pinduoduo-BjQZUCNOcAKTo4XQtr8rVA==/base.apk";
        /// <summary>p84/p93 = "{时间戳ms}_{序号}"。</summary>
        public const string P84Plain = "1783813690053_1";
        public const string P93Plain = "1783813690053_1";
        /// <summary>p98 = 4 条 "{ts},{id100-103},67,{5B hex};" 检测/计时记录 (非签名)。</summary>
        public const string P98Plain =
            "1783813690048,100,67,8d927ea23f;1783813690048,101,67,c761c326c0;" +
            "1783813690053,102,67,434cb953ff;1783813690053,103,67,9038e303e2;";

        // report_03 报文时间基线
        public const long ReportTsBaseline = 1783813690041; // p61
        public const long InstallTsBaseline = 1779712666437; // p97

        private static byte[] Hex(string s)
        {
            var b = new byte[s.Length / 2];
            for (int i = 0; i < b.Length; i++)
                b[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
            return b;
        }
    }
}
