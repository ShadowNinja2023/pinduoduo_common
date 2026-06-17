using System;
using System.Text;

namespace PddLib.Register
{
    /// <summary>
    /// 组装 04 报文的 fk_data 字段 (风控反检测主结构, 原样 JSON, 不做 url 编码)。
    ///
    /// 结构 (见 11_request04_meta_info_analysis.md 第六节):
    ///   {
    ///     "extra":{"dynso_load_ts":"<libdyncommon 加载时刻 ms>",
    ///              "dynso_load_rand":"<10位随机>","dyna_rom_dect_vern":"0.0.3"},
    ///     "hwmusic":{...全 "0" + sdk},
    ///     "inline_hook":"<7 段, 每段12字节机器码 = 关键函数入口字节快照>",
    ///     "got_hook":"lib64/","a2":"-1"
    ///   }
    ///
    /// mock 策略: 复刻"干净基线"(未被 hook 的入口字节)。inline_hook 段直接用样本基线值,
    /// 代表监控函数未被 inline hook; dynso_load_ts 取本次会话时刻, dynso_load_rand 随机。
    /// </summary>
    public static class FkDataBuilder
    {
        /// <summary>inline_hook: 7 段关键函数入口前 12 字节机器码 (干净基线, 取自样本; 未被 hook)。</summary>
        public const string InlineHookClean =
            "5f2403d5e20301aae10300aa,3f2303d5ffc301d1fd7b01a9,3f2303d5ff4301d1fd7b01a9," +
            "5f2403d5e203012ae10300aa,5f2403d5e20301aae10300aa,ff0301d1f44f02a9fd7b03a9," +
            "ff4303d1ea2b00fde923066d";

        public const string GotHookClean = "lib64/";
        public const string A2Clean = "-1";
        public const string DynaRomDectVern = "0.0.3";

        /// <summary>
        /// 生成 fk_data 原样 JSON。
        /// </summary>
        /// <param name="dynsoLoadTsMs">libdyncommon 加载时间戳 ms (与 03 dynso_load_ts 同源/联动)</param>
        /// <param name="dynsoLoadRand">加载随机数 (10 位数字字符串)</param>
        /// <param name="sdk">Android SDK level (Android15=35)</param>
        public static string Build(long dynsoLoadTsMs, string dynsoLoadRand, int sdk = 35)
        {
            var sb = new StringBuilder(512);
            sb.Append("{\"extra\":{")
              .Append("\"dynso_load_ts\":\"").Append(dynsoLoadTsMs).Append("\",")
              .Append("\"dynso_load_rand\":\"").Append(dynsoLoadRand).Append("\",")
              .Append("\"dyna_rom_dect_vern\":\"").Append(DynaRomDectVern).Append("\"},");
            sb.Append("\"hwmusic\":{")
              .Append("\"is_trgt_file_exist\":\"0\",\"lnkr_dect_rslt\":\"0\",")
              .Append("\"librt_dect_rslt\":\"0\",\"lpjdk_dect_rslt\":\"0\",")
              .Append("\"prop_dect_rslt\":\"0\",\"sdk\":\"").Append(sdk).Append("\"},");
            sb.Append("\"inline_hook\":\"").Append(InlineHookClean).Append("\",");
            sb.Append("\"got_hook\":\"").Append(GotHookClean).Append("\",");
            sb.Append("\"a2\":\"").Append(A2Clean).Append("\"}");
            return sb.ToString();
        }

        /// <summary>mock 默认: dynso_load_ts 取当前时刻, rand 随机 10 位。</summary>
        public static string BuildMock(long? dynsoLoadTsMs = null)
        {
            long ts = dynsoLoadTsMs ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            string rand = Random.Shared.NextInt64(0, 10_000_000_000L).ToString("D10");
            return Build(ts, rand);
        }
    }
}
