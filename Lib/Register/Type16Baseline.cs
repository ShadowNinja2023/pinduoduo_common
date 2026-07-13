using System;
using System.IO;

namespace PddLib.Register
{
    /// <summary>
    /// data_type=16 报文 r 字段的 proc-maps 路径清单基线。
    ///
    /// 明文 = ';' 分隔的 <c>/proc/self/maps</c> 路径/区域名清单 (干净样本 1310 项, 见 docs 17)。
    /// 属**机型 / ROM / app 版本相关**数据: 系统框架部分 (boot*.art / /apex / linker64 / *.oat)
    /// 随 ROM 固定, 应用部分 (.so 列表 / dalvik 匿名段) 随 app 版本固定。
    /// ★ 红线: 清单里不能出现 frida/gadget/substrate/xposed 等注入痕迹, 干净样本天然满足。
    ///
    /// 数据文件 <c>Data/Type16/maps_regions.txt</c> 随项目输出流转 (csproj Content)。
    /// </summary>
    public static class Type16Baseline
    {
        private static string? _cached;

        /// <summary>干净 maps 路径清单 (原始明文, ';' 分隔)。取自干净流程样本。</summary>
        public static string MapsRegions
        {
            get
            {
                if (_cached != null) return _cached;
                string path = Path.Combine(AppContext.BaseDirectory, "Data", "Type16", "maps_regions.txt");
                _cached = File.Exists(path) ? File.ReadAllText(path) : "";
                return _cached;
            }
        }
    }
}
