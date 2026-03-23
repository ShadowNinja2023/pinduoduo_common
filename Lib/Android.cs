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

        public Android(Session session, Device device, string? proxyUrl = null, string? proxyUsername = null, string? proxyPassword = null)
        {
            Session = session;
            Device = device;
            Http = new Http(proxyUrl, proxyUsername, proxyPassword);
        }

        /// <summary>
        /// 构建业务公共请求头
        /// </summary>
        private Dictionary<string, string> BuildHeaders(Dictionary<string, string>? extra = null)
        {
            var headers = new Dictionary<string, string>
            {
                ["AccessToken"] = Session.AccessToken,
                ["Referer"] = "Android",
                ["Content-Type"] = "application/json;charset=UTF-8",
            };
            if (extra != null)
            {
                foreach (var kv in extra)
                    headers[kv.Key] = kv.Value;
            }
            return headers;
        }

        /// <summary>
        /// 获取商品详情 (integration/render)
        /// </summary>
        /// <param name="goodsId">商品ID</param>
        public async Task<string> GetItemDetailAsync(string goodsId)
        {
            var url = $"{ApiBase}/api/oak/integration/render";
            var now = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

            var body = new Dictionary<string, object>
            {
                ["goods_id"] = goodsId,
                ["page_sn"] = "10014",
                ["page_id"] = $"10014_{now}_1901484493",
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
                // _oak_rcto 由 H5 JS Bridge 生成，纯 HTTP 模拟传空即可
                ["_oak_rcto"] = "",
                ["union_pay_installed"] = true,
                ["client_lab"] = new Dictionary<string, string>
                {
                    ["mall_h5_url_preload_enable"] = "1"
                },
                ["is_sys_minor"] = 0,
                ["system_language"] = "zh",
                ["impr_tips"] = Array.Empty<object>(),
                ["screen_height"] = 794,
                ["screen_width"] = 375,
                ["goods_detail_support_zoom"] = "true",
                ["pdd_goods_detail_dark_color_enable"] = true,
            };

            var headers = BuildHeaders(new Dictionary<string, string>
            {
                ["ETag"] = "vNp2nq8p",
            });

            return await Http.PostAsync(url, body, headers);
        }
    }
}
