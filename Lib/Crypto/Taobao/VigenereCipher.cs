using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib.Crypto.Taobao
{
    internal static class VigenereCipher
    {
        /// <summary>
        /// 逆 Vigenere 解密
        /// p = (c - 0x20 - (k - 0x20)) % 95 + 0x20
        /// </summary>
        public static byte[] Decrypt(byte[] data, byte[] key, int offset = 0)
        {
            var plain = new byte[data.Length];
            int ki = offset;
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                if (b >= 0x20 && b <= 0x7e)
                {
                    int c = b - 0x20;
                    int k = key[ki % key.Length] - 0x20;
                    int p = ((c - k) % 95 + 95) % 95; // 确保非负
                    plain[i] = (byte)(p + 0x20);
                }
                else
                {
                    plain[i] = b;
                }
                ki++; // 非 ASCII 也推进 key 索引 (与 SO 行为一致)
            }
            return plain;
        }
    }
}
