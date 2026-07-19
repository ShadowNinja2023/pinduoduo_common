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

        /// <summary>7.77.0 app 内置 event_token (assets/component/event_token.json)。已用 01.trace 端到端验签。</summary>
        public const string EventToken777 = "006AFBe_xJ0-ViV1fuCg0aLmi9v_t13u9Fi2GrCiBiH7nUepEdYILKeB94I5TGZJFu7vF";

        /// <summary>8.8.0 app 内置 event_token。当前 mock 设备用 8.8.0, 默认用此。</summary>
        public const string EventToken880 = "00dAFBWlnDxDmm1h+WwNyxLmi9Tt3td_tfAoHTR+xlHGFLX5IDjUrb2AG2lpJFwRWBa+W";

        /// <summary>
        /// 日志埋点 sctk 签名 (无 stack/env 形式, 占真机 161/181, 已用 01.trace 端到端验签 20/20)。
        /// 对 <paramref name="rctkPost"/> (记录里 &amp;sctk= 之前的原串) 用 record 的 time 作 rctk_ts 签名。
        /// 输出格式: {base64(doubleHash)}0{nonce}01#{token_head(45)}
        /// 默认按 8.8.0 (当前 mock 设备版本); 验 7.77.0 真机样本时显式传 version/token。
        /// </summary>
        public static string SignLog(string rctkPost, string timestamp,
            string version = "8.8.0", string token = EventToken880)
        {
            string nonce = GetNonce();
            string rctkToken = token.Substring(token.Length - 24);   // 尾 24 = rctk_token
            string head = token.Substring(0, token.Length - 24);     // 前 45 = token_head
            string hashInput = $"rctk_plat=Android&rctk_ver={version}&rctk_ts={timestamp}" +
                               $"&rctk_nonce={nonce}&rctk_rpkg=0&rctk_post={rctkPost}&rctk_token={rctkToken}";
            string b64 = Convert.ToBase64String(CustomSHA256.DoubleHash(Encoding.UTF8.GetBytes(hashInput)));
            return $"{b64}0{nonce}01#{head}";
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
