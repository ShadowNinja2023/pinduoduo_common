using System;
using System.Security.Cryptography;
using System.Text;

namespace PddLib.Register
{
    /// <summary>
    /// p47 生成器 — native 自产的随机会话标识 (libpdd_secure.so 内部, 非 JNI/str5 传入)。
    ///
    /// 实证: trace 显示 p47 的 jstring 由 native NewStringUTF 创建 (sub_175AF8); ng2 的 str5
    /// 与 sdr 入参 map 均无 p47。每会话随机生成, 是 x-p1 的 RC4 key 来源 (MD5(p47))。
    ///
    /// 格式: 8-4-4-4-12, 共 32 个 [A-Za-z0-9] 字符 + 4 个 '-', 例 "S5n3Bd6L-ofNf-Zv3q-402e-4yHlPVhy5foo"。
    ///
    /// mock: 自由生成, 但同一会话内必须三处一致 —— 报文 p47 字段 / x-p1 明文头 / x-p1 RC4 key=MD5(p47)。
    /// 服务端只校验 x-p1 自签名一致性, 不校验 p47 内容 → 随机值即可, 无服务端依赖。
    /// </summary>
    public static class P47Generator
    {
        private const string Charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        private static readonly int[] SegLens = { 8, 4, 4, 4, 12 };

        /// <summary>生成一个新的 p47 (8-4-4-4-12, [A-Za-z0-9])。</summary>
        public static string New()
        {
            var sb = new StringBuilder(36);
            for (int s = 0; s < SegLens.Length; s++)
            {
                if (s > 0) sb.Append('-');
                for (int i = 0; i < SegLens[s]; i++)
                    sb.Append(Charset[RandomNumberGenerator.GetInt32(Charset.Length)]);
            }
            return sb.ToString();
        }

        /// <summary>校验 p47 是否符合格式 (8-4-4-4-12 的 [A-Za-z0-9])。</summary>
        public static bool IsValid(string p47)
        {
            if (string.IsNullOrEmpty(p47)) return false;
            string[] parts = p47.Split('-');
            if (parts.Length != SegLens.Length) return false;
            for (int s = 0; s < SegLens.Length; s++)
            {
                if (parts[s].Length != SegLens[s]) return false;
                foreach (char c in parts[s])
                    if (Charset.IndexOf(c) < 0) return false;
            }
            return true;
        }

        /// <summary>x-p1 用的 RC4 key = MD5(p47) (16 字节)。</summary>
        public static byte[] Md5Key(string p47)
        {
            using var md5 = MD5.Create();
            return md5.ComputeHash(Encoding.ASCII.GetBytes(p47));
        }
    }
}
