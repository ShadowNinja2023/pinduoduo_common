using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib
{
    public class Utils
    {
        public static string GetRandomChars(int length)
        {
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

            var result = new char[length];
            for (int i = 0; i < result.Length; i++)
            {
                result[i] = chars[Random.Shared.Next(chars.Length)];
            }
            return new string(result);
        }
    }
}
