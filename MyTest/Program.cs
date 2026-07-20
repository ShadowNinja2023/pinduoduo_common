using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using PddLib;
using PddLib.Crypto;
using PddLib.Crypto.Extra;
using System.Web;

namespace MyTest
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            // 持久化文件: 存在则复用(免重复注册/登录), 否则注册+登录后保存。
            // 删除该文件即可强制重新注册一台新设备。
            string statePath = Path.Combine(AppContext.BaseDirectory, "android_state.json");

            Android android;
            if (Android.StateExists(statePath))
            {
                Console.WriteLine($"[加载] 复用持久化设备状态: {statePath}");
                android = Android.LoadState(statePath, "http://127.0.0.1:8888");
                Console.WriteLine($"  pddid={android.Pddid}  机型={android.Device.Brand}/{android.Device.Model}  uid={android.Session.Uid}");
            }
            else
            {
                Console.WriteLine("[新建] 无存档 → 注册 + 登录新设备...");
                android = await Android.CreateNewAsync("http://127.0.0.1:8888");

                android.SmsCodeProvider = async (ctx) =>
                {
                    Console.WriteLine($"请输入验证码 , 发送到 {ctx.Mobile} :");
                    var input = Console.ReadLine();
                    return input ?? "";
                };

                var login = await android.Login("15578898540", "86", "1");
                if (login.Success)
                {
                    android.SaveState(statePath);
                    Console.WriteLine($"[保存] 登录成功, 已持久化: {statePath}");
                }
                else
                {
                    Console.WriteLine($"[警告] 登录未成功 ({login.Stage}: {login.Message}), 未保存状态");
                }

                await android.ReportMetaInfoAsync();
            }

            string goodsId = "237907536111";

            //var search = await android.SearchFullAsync("牙刷", 1, 20);

            var item = await android.GetItemDetailViaHomeAsync();

            Console.WriteLine($"完成 pddid={android.Pddid}  机型={android.Device.Brand}/{android.Device.Model}");
        }
    }
}
