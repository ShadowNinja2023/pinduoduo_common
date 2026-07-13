using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib
{
    public static class Log
    {
        private static void WriteLog(string level, string message)
        {
            Console.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}");
        }
        public static void Debug(string message)
        {
            WriteLog("DEBUG", message);
        }

        public static void Info(string message)
        {
            WriteLog("INFO", message);
        }
    }
}
