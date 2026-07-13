using PddLib;
using PddLib.Crypto;
using PddLib.Crypto.Extra;

namespace MyTest
{
    internal class Program
    {
        static async Task Main(string[] args)
        {
            var android = await Android.CreateNewAsync("http://127.0.0.1:8888");

            android.SmsCodeProvider = async (ctx) =>
            {
                Console.WriteLine($"请输入验证码 , 发送到 {ctx.Mobile} :");
                var input = Console.ReadLine();
                return input ?? "";
            };

            await android.Login("13152661990", "86", "1");

            //await android.Login("18978882486","");

            var item = await android.GetItemDetailFullAsync("879284704680");
            Console.WriteLine($"注册成功 pddid={android.Pddid}  机型={android.Device.Brand}/{android.Device.Model}");
        }
    }
}
