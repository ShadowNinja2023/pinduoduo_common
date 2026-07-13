using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Tls.Crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace PddLib.Crypto.Taobao
{
    public class RepedCrypto
    {
        private static readonly string outSideAesKey = "efdacedca8a69cde0b1711c8de9df510";
        private static readonly string outSideAesIv = "efdacedca8a69cde0b1711c8de9df510";

        private class V0001Decoder
        {
            public static List<KeyValuePair<int, byte[]>> Decode(string base64String)
            {
                return Decode(Convert.FromBase64String(base64String));
            }

            public static List<KeyValuePair<int, byte[]>> Decode(byte[] bytes)
            {
                var header = bytes.Take(12).ToArray();
                //中间的第13位应该是body加密方式，跟后边的逻辑一样 v0001 是22 =0x16 v0002是19 = 0x13
                var body = bytes.Skip(13).ToArray();

                //第一层解密，头部4字节,从第3个字节开始xor
                var header1 = body.Take(4).ToArray();

                var body1 = body.Skip(4).ToArray();
                var bodyDecode = Algorithm.DecodeByHeaders4(body1, header1);

                //第二层解密，行列移动
                var bytes2 = Algorithm.DecodeByBox(bodyDecode);

                //第三层，外层头部异或，这个外部异或是从第一个字节开始xor，跟前面的不一样
                var xorHeader = header.Skip(2).Take(4).ToArray();

                for (var i = 0; i < bytes2.Length; i++)
                {
                    bytes2[i] = (byte)(bytes2[i] ^ xorHeader[i % xorHeader.Length]);
                }

                //接下来是分段的加密拼接
                //转hexstring可能比较好处理一点
                var dataList = new List<string>();
                var decodeList = new List<KeyValuePair<int, byte[]>>();
                var hexString = bytes2.ToHexString();

                for (var i = 0; i < hexString.Length;)
                {
                    //开始2个字节明确是长度，转为小端序
                    //中间的0000也可能是长度，用来预留给超长数据，统一当小端序先处理
                    var length = Algorithm.ConvertHexLittleEndianToInt(hexString.Substring(i, 8));
                    i += 8;
                    var data = hexString.Substring(i, length * 2);
                    i += length * 2;

                    dataList.Add(data);
                }
                //统一解密
                foreach (var item in dataList)
                {
                    var itemBytes = item.FromHexString();
                    decodeList.Add(Algorithm.ProcessDecode(itemBytes));
                }

                return decodeList;
            }


        }

        private class V0003Decoder
        {
            public static List<KeyValuePair<int, byte[]>> Decode(string base64String)
            {
                return Decode(Convert.FromBase64String(base64String));
            }

            public static List<KeyValuePair<int, byte[]>> Decode(byte[] bytes)
            {
                var header = bytes.Take(12).ToArray();
                var body = bytes.Skip(12).ToArray();

                var aesResult = AesCrypto.Decrypt(body, "be51496ce187c86b95c346c9ba9cbd14".FromHexString(), "be51496ce187c86b95c346c9ba9cbd14".FromHexString());

                var xorHeader = header.Skip(4).Take(4).ToArray();

                for (var i = 0; i < aesResult.Length; i++)
                {
                    aesResult[i] = (byte)(aesResult[i] ^ xorHeader[i % xorHeader.Length]);
                }

                var groups = new List<byte[]>();
                while (aesResult.Length > 0)
                {
                    var length = Algorithm.ConvertHexLittleEndianToInt(aesResult.Take(4).ToArray().ToHexString());

                    groups.Add(aesResult.Skip(4).Take(length).ToArray());

                    aesResult = aesResult.Skip(4 + length).ToArray();
                }

                var decodeList = new List<KeyValuePair<int, byte[]>>();
                foreach (var group in groups)
                {
                    decodeList.Add(Algorithm.ProcessDecode(group));
                }


                return decodeList;
            }

        }


        private static string DecodeOutside(byte[] bytes)
        {

            var aesDecode = AesCrypto.Decrypt(bytes, outSideAesKey.FromHexString(), outSideAesIv.FromHexString());

            var result = Zlib.Decompress(aesDecode);

            return Encoding.UTF8.GetString(result);

        }

        public static (string raw,List<DetectItem> detectItems) Decode(string body)
        {
            var raw = DecodeOutside(Convert.FromBase64String(body));
            var es = raw.ToJObject()["et"]["es"].ToString();
            string deviceJson = null;
            if (es.StartsWith("v0001"))
            {
                deviceJson = DecodeKeyValuePairsToJson(V0001Decoder.Decode(es.Substring(14)));
            }
            else
            {
                deviceJson = DecodeKeyValuePairsToJson(V0003Decoder.Decode(es.Substring(14)));
            }

            var detectItems = LegacyConverter.Convert(deviceJson.FromJson<List<LegacyItem>>());

            return (raw, detectItems);
        }

        private static string DecodeKeyValuePairsToJson(List<KeyValuePair<int, byte[]>> decodeList)
        {
            var result = new List<KeyValuePair<int, Dictionary<string, string>>>();

            foreach (var item in decodeList)
            {
                result.Add(new KeyValuePair<int, Dictionary<string, string>>(item.Key, GetDictionary(item.Value)));
            }

            return result.SelectMany(x => x.Value).ToJson();
        }

        private static Dictionary<string, string> GetDictionary(byte[] data)
        {
            var result = new Dictionary<string, string>();
            var skip = 0;
            while (data.Skip(skip).Count() > 0)
            {
                var bytes = data.Skip(skip);
                var totalLength = Algorithm.ConvertHexLittleEndianToInt(bytes.Skip(4).Take(4).ToArray().ToHexString());
                var keyValue = bytes.Take(totalLength);

                var keyLength = Algorithm.ConvertHexLittleEndianToInt(keyValue.Skip(12).Take(4).ToArray().ToHexString());
                var key = Encoding.UTF8.GetString(keyValue.Skip(16).Take(keyLength - 4).ToArray());

                //去掉分隔符
                key = System.Text.RegularExpressions.Regex.Split(key, "Yrmc")[0];

                var valueLength = Algorithm.ConvertHexLittleEndianToInt(keyValue.Skip(16 + keyLength).Take(4).ToArray().ToHexString());
                var value = Encoding.UTF8.GetString(keyValue.Skip(20 + keyLength).Take(valueLength).ToArray());

                result[key] = value;

                skip += totalLength;
            }

            return result;
        }
    }
}
