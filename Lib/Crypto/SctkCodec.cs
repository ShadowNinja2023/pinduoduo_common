using PddLib.Crypto.Taobao;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib.Crypto
{
    public class SctkCodec
    {
        private static string GetNonce()
        {
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

            var result = new char[32];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = chars[Random.Shared.Next(chars.Length)];
            }
            return new string(result);
        }

        /// <summary>
        /// 日志发送sctk
        /// </summary>
        /// <param name="input"></param>
        /// <param name="timestamp"></param>
        /// <param name="version">apk版本</param>
        /// <param name="event_token">apk打包里面的assets/component/event_token.json 更换版本需要替换</param>
        /// <param name="rctk_stack">这里主要是ts生成函数的堆栈哈希结果，最好根据真实值替换写死 hook strlen应该能看到真机的值</param>
        /// <param name="rctk_env">应该是固定或者版本固定</param>
        /// <returns></returns>
        public static string GetSctk(string input, string timestamp, string version = "7.70.0", string event_token = "00022Bm2MwAcMgCbjptzkrROatF_t13uz_1XJ++bmmf5XyYRV3f6gHD3ePbh+7Mz0EzB0", string rctk_stack = "777cac1b8d0f8f04", string rctk_env = "DZ1sUUsMbL4=")
        {
            //string testInput = "rctk_plat=Android&rctk_ver=7.70.0&rctk_ts=1769623749309&rctk_nonce=GyI1e4zIoSY9J6OODzk3ibth4f08tDle&rctk_rpkg=0&rctk_post=hello&rctk_token=yYRV3f6gHD3ePbh+7Mz0EzB0&rctk_stack=777cac1b8d0f8f04&rctk_env=DZ1sUUsMbL4=";
            //string firstHashHex = ZGJ.PDD.CustomSHA256.DoubleHashString(testInput);
            string nonce = GetNonce();
            string rctk_token = event_token.Substring(event_token.Length - 24);
            string hashInput = $"rctk_plat=Android&rctk_ver={version}&rctk_ts={timestamp}&rctk_nonce={nonce}&rctk_rpkg=0&rctk_post={input}&rctk_token={rctk_token}&rctk_stack={rctk_stack}&rctk_env={rctk_env}";
            string hashResult = Crypto.CustomSHA256.DoubleHashString(hashInput);
            string hashBase64 = Convert.ToBase64String(hashResult.FromHexString());

            //2Y586SW0fHvPLkdNVbn5IvGDgJrmIj+Dv1rnqvOybtU=0GyI1e4zIoSY9J6OODzk3ibth4f08tDle01#00022Bm2MwAcMgCbjptzkrROatF_t13uz_1XJ++bmmf5X#777cac1b8d0f8f04#DZ1sUUsMbL4=
            string result = $"{hashBase64}0{nonce}01#{event_token.Replace(rctk_token, "")}#{rctk_stack}#{rctk_env}";

            return result;
        }
    }
}
