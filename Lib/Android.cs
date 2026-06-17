using System.Text.Json;
using PddLib.Models;

namespace PddLib
{
    /// <summary>
    /// Android 主类，通过会话和设备信息创建实例，调用业务接口
    /// </summary>
    public class Android
    {
        public Device Device { get; }
        public Session Session { get; }
        public Http Http { get; }

        private const string ApiBase = "https://api.pinduoduo.com";
        private const string AppVersion = "7.99.0";

        public Android(Session session, Device device, string? proxyUrl = null, string? proxyUsername = null, string? proxyPassword = null)
        {
            Session = session;
            Device = device;
            Http = new Http(proxyUrl, proxyUsername, proxyPassword);
        }

        /// <summary>
        /// 解析 pixels "2288*1080" => (height, width)
        /// </summary>
        private (int height, int width) ParsePixels()
        {
            var parts = Device.Pixels?.Split('*');
            if (parts?.Length == 2
                && int.TryParse(parts[0], out var h)
                && int.TryParse(parts[1], out var w))
                return (h, w);
            return (2400, 1080);
        }

        /// <summary>
        /// 构建业务公共请求头（对齐实际抓包）
        /// </summary>
        private Dictionary<string, string> BuildHeaders(Dictionary<string, string>? extra = null, bool useInfo4 = false)
        {
            var (height, width) = ParsePixels();
            var osv = Device.DeviceInfo?.VersionRelease ?? "14";
            var build = Device.DeviceInfo?.Build;
            var fingerprint = build?.Fingerprint ?? "";

            // user-agent: android Mozilla/5.0 (Linux; Android {osv}; {model} Build/{buildId}; wv) ...
            var ua = $"android Mozilla/5.0 (Linux; Android {osv}; {Device.Model} Build/{build?.Id ?? "TP1A.220624.014"}; wv) " +
                     $"AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/143.0.7499.192 Safari/537.36 " +
                     $" phh_android_version/{AppVersion} phh_android_build/{Session.Acid}" +
                     $" phh_android_channel/main_guanwang pversion/0";

            // x-pdd-queries: width={w}&height={h}&net=1&brand={brand}&model={model}&osv={osv}&appv={appv}&pl=2
            var queries = $"width={width}&height={height}&net=1&brand={Device.Brand}&model={Device.Model}&osv={osv}&appv={AppVersion}&pl=2";

            var headers = new Dictionary<string, string>
            {
                ["accesstoken"] = Session.AccessToken,
                ["etag"] = "", //服务器下发，先放空
                ["referer"] = "Android",
                ["content-type"] = "application/json;charset=UTF-8",
                ["user-agent"] = ua,
                ["accept-encoding"] = "gzip",
                ["accept-language"] = "zh-Hans-CN",
                ["p-appname"] = "pinduoduo",
                ["p-mediainfo"] = "player=1.0.3&rtc=1.0.0",
                ["p-proc"] = "main",
                ["x-app-lang"] = "zh",
                ["x-pdd-queries"] = queries,
                ["pdd-config"] = "V4:001.079900",
                ["multi-set"] = "1,1,100000824",
                ["x-app-ui"] = "dm=0&zm=0",
                ["x-pdd-info"] = "bold_free=false&bold_product=&front=1&tz=Asia/Shanghai",
            };

            if (extra != null)
            {
                foreach (var kv in extra)
                    headers[kv.Key] = kv.Value;
            }

            if (useInfo4)
            {
                headers["anti-token"] = Crypto.Info4Codec.Encrypt(Crypto.Info4Codec.BuildPlaintext(Device.Imei[..16], DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), "",Guid.Parse(Device.Imei)));
            }

            return headers;
        }

        /// <summary>
        /// 获取商品详情 (integration/render)，返回完整 HTTP 结果
        /// </summary>
        public async Task<HttpResult> GetItemDetailFullAsync(string goodsId)
        {
            var url = $"{ApiBase}/api/oak/integration/render";
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            Device.Brand = "";
            Device.Model = "MNA-AL00";

            var body = new Dictionary<string, object>
            {
                ["goods_id"] = goodsId,
                ["page_sn"] = "10014",
                ["page_id"] = $"10014_{now}_{Random.Shared.NextInt64(1000000000, 9000000000)}",
                ["page_from"] = "35",
                ["page_version"] = "7",
                ["client_time"] = now.ToString(),
                ["refer_page_sn"] = "10002",
                ["refer_page_el_sn"] = "99862",
                ["phone_model"] = Device.Model,
                ["pic_w"] = 0,
                ["pic_h"] = 0,
                ["has_pic_url"] = 1,
                ["address_list"] = Array.Empty<object>(),
                ["extend_map"] = new Dictionary<string, object>(),
                ["_oak_rcto"] = "",
                ["union_pay_installed"] = true,
                ["client_lab"] = new Dictionary<string, string>
                {
                    ["mall_h5_url_preload_enable"] = "1"
                },
                ["is_sys_minor"] = 0,
                ["system_language"] = "zh",
                ["impr_tips"] = Array.Empty<object>(),
                ["screen_height"] = ParsePixels().height,
                ["screen_width"] = ParsePixels().width,
                ["goods_detail_support_zoom"] = "true",
                ["pdd_goods_detail_dark_color_enable"] = true,
            };

            return await Http.PostFullAsync(url, body, BuildHeaders(useInfo4:true));
        }

        /// <summary>
        /// 获取商品详情，仅返回 body 字符串
        /// </summary>
        public async Task<string> GetItemDetailAsync(string goodsId)
        {
            var result = await GetItemDetailFullAsync(goodsId);
            return result.Body;
        }
    }
}
