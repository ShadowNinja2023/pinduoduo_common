using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib.Crypto.Taobao
{
    public class AesCrypto
    {
        private static byte[] CipherData(PaddedBufferedBlockCipher cipher, byte[] data)
        {
            int minSize = cipher.GetOutputSize(data.Length);
            byte[] outBuf = new byte[minSize];
            int length1 = cipher.ProcessBytes(data, 0, data.Length, outBuf, 0);
            int length2 = cipher.DoFinal(outBuf, length1);
            int actualLength = length1 + length2;
            byte[] result = new byte[actualLength];
            Array.Copy(outBuf, 0, result, 0, result.Length);
            return result;
        }

        public static byte[] Decrypt(string data, string key, string iv)
        {
            return Decrypt(data, Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(iv));
        }

        public static string DecryptToUTF8(string data, string key, string iv)
            => Encoding.UTF8.GetString(Decrypt(data, Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(iv)));

        public static byte[] Decrypt(string data, byte[] key, byte[] iv)
        {
            PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CbcBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine()), new Pkcs7Padding());
            var ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
            aes.Init(false, ivAndKey);
            return CipherData(aes, Convert.FromBase64String(data));
        }

        public static byte[] Decrypt(byte[] data, byte[] key, byte[] iv)
        {
            PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CbcBlockCipher(new Org.BouncyCastle.Crypto.Engines.AesEngine()), new Pkcs7Padding());
            var ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
            aes.Init(false, ivAndKey);
            return CipherData(aes, data);
        }

        public static byte[] Encrypt(byte[] plain, string key, string iv)
        {
            return Encrypt(plain, Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(iv));
        }

        public static byte[] Encrypt(byte[] plain, byte[] key, byte[] iv)
        {
            PaddedBufferedBlockCipher aes = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            var ivAndKey = new ParametersWithIV(new KeyParameter(key), iv);
            aes.Init(true, ivAndKey);
            return CipherData(aes, plain);
        }
    }
}
