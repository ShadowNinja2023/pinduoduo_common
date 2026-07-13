using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib.Crypto.Taobao
{
    public static class Extensions
    {
        public static byte[] FromHexString(this string hex)
        {
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Hex string must have an even length.");

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
            {
                string byteValue = hex.Substring(i, 2); // 每两个字符一组
                bytes[i / 2] = byte.Parse(byteValue, NumberStyles.HexNumber); // 转换为字节
            }
            return bytes;
        }

        public static string ToJson(this object obj)
        {
            return Newtonsoft.Json.JsonConvert.SerializeObject(obj);
        }

        public static T FromJson<T>(this string obj)
        {
            return Newtonsoft.Json.JsonConvert.DeserializeObject<T>(obj, new Newtonsoft.Json.JsonSerializerSettings { DateTimeZoneHandling = DateTimeZoneHandling.Local });
        }

        public static JObject ToJObject(this string obj)
        {
            return Newtonsoft.Json.JsonConvert.DeserializeObject<JObject>(obj);
        }

        public static JArray ToJArray(this string obj)
        {
            return Newtonsoft.Json.JsonConvert.DeserializeObject<JArray>(obj);
        }

        public static string ToHexString(this byte[] byteArray)
        {
            StringBuilder hex = new StringBuilder(byteArray.Length * 2);
            foreach (byte b in byteArray)
            {
                hex.AppendFormat("{0:X2}", b); // Converts to uppercase hexadecimal format.
            }
            return hex.ToString();
        }
    }
}
