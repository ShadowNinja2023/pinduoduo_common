using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib.Crypto
{
    public class CustomSHA256
    {
        #region 常量定义

        /// <summary>
        /// 标准SHA-256的K常量（64个）
        /// 注：原始实现中这些K常量通过SBOX编码存储，运行时解码
        /// 为简化实现，这里直接使用解码后的标准值
        /// </summary>
        private static readonly uint[] K = new uint[]
        {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        /// <summary>
        /// 第1轮哈希 IV (10 个 dword: 8 state + 2 附加, 来自 sub_12BD04 mode=1)。
        /// 前 8 个是初始 state, [8]/[9] 参与压缩前的 state shuffle。字节级验证。
        /// </summary>
        private static readonly uint[] IV1 = {
            0xc7e9f9cf, 0x2471d5a9, 0x85cc7ac3, 0xc95afe6e,
            0xd64339aa, 0x9e0806ba, 0x3e213b45, 0xa818299d,
            0x12c2c280, 0x226a8864
        };

        /// <summary>第2轮哈希 IV (10 dword, 来自 sub_12BD04 mode=2)。</summary>
        private static readonly uint[] IV2 = {
            0x5103d887, 0xf6580e91, 0x7aced7da, 0xcf4be428,
            0x748f7ebb, 0xf84144a7, 0x6645f081, 0x1a3c2ca5,
            0xa937dfca, 0x85e1bca0
        };

        #endregion

        #region 辅助方法

        /// <summary>
        /// 循环右移（Rotate Right）
        /// </summary>
        private static uint ROTR(uint n, int b)
        {
            return (n >> b) | (n << (32 - b));
        }

        /// <summary>
        /// 字节数组转十六进制字符串
        /// </summary>
        private static string BytesToHex(byte[] bytes)
        {
            char[] hex = new char[bytes.Length * 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                int b = bytes[i];
                hex[i * 2] = GetHexChar(b >> 4);
                hex[i * 2 + 1] = GetHexChar(b & 0x0F);
            }
            return new string(hex);
        }

        private static char GetHexChar(int value)
        {
            return (char)(value < 10 ? '0' + value : 'a' + value - 10);
        }

        #endregion

        #region SHA-256核心算法

        /// <summary>
        /// SHA-256压缩函数
        /// </summary>
        /// <param name="state">当前哈希状态（8个uint）</param>
        /// <param name="block">数据块</param>
        /// <param name="offset">数据块在数组中的起始位置</param>
        private static void SHA256Transform(uint[] state, byte[] block, int offset)
        {
            // 消息扩展数组（W数组）
            uint[] w = new uint[64];

            // 前16个字直接从block读取（大端序）
            for (int i = 0; i < 16; i++)
            {
                int pos = offset + i * 4;
                w[i] = ((uint)block[pos] << 24) |
                       ((uint)block[pos + 1] << 16) |
                       ((uint)block[pos + 2] << 8) |
                       ((uint)block[pos + 3]);
            }

            // 消息扩展：生成剩余48个字
            for (int i = 16; i < 64; i++)
            {
                uint s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >> 3);
                uint s1 = ROTR(w[i - 2], 17) ^ ROTR(w[i - 2], 19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16] + s0 + w[i - 7] + s1;
            }

            // 初始化工作变量
            uint a = state[0];
            uint b = state[1];
            uint c = state[2];
            uint d = state[3];
            uint e = state[4];
            uint f = state[5];
            uint g = state[6];
            uint h = state[7];

            // 64轮主循环
            for (int i = 0; i < 64; i++)
            {
                uint S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
                uint ch = (e & f) ^ (~e & g);
                uint temp1 = h + S1 + ch + K[i] + w[i];

                uint S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
                uint maj = (a & b) ^ (a & c) ^ (b & c);
                uint temp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            // 更新状态
            state[0] += a;
            state[1] += b;
            state[2] += c;
            state[3] += d;
            state[4] += e;
            state[5] += f;
            state[6] += g;
            state[7] += h;
        }

        /// <summary>
        /// 单次魔改 SHA-256 哈希 (字节级对齐 libpdd_secure)。
        /// 魔改点: 1) 10-dword IV; 2) 压缩前用 [8]/[9] 做 state shuffle; 3) bit counter 初始 0x200。
        /// </summary>
        /// <param name="data">输入数据</param>
        /// <param name="iv">初始向量 (10 个 uint)</param>
        /// <returns>32字节哈希值</returns>
        private static byte[] CustomSHA256Hash(byte[] data, uint[] iv)
        {
            uint[] state = new uint[10];
            Array.Copy(iv, state, 10);

            // 压缩前 state shuffle (sub_12AE08 开头): 用附加的 [8]/[9] 混入
            uint s0 = state[0], s1 = state[1], s2 = state[2], s3 = state[3];
            uint s4 = state[4], s5 = state[5], s6 = state[6];
            uint s8 = state[8], s9 = state[9];
            state[7] = s6;
            state[6] = s5;
            state[5] = s4;
            state[4] = s8 + s3;
            state[3] = s2;
            state[2] = s1;
            state[1] = s0;
            state[0] = s9 + s8;

            // bit counter 初始 0x200 (= 64*8), 等价长度字段 = (len+64)*8
            long bitLen = 0x200L + (long)data.Length * 8;

            int originalLength = data.Length;
            int paddingLength = (64 - ((originalLength + 9) % 64)) % 64;
            int totalLength = originalLength + 1 + paddingLength + 8;

            byte[] paddedData = new byte[totalLength];
            Array.Copy(data, 0, paddedData, 0, originalLength);
            paddedData[originalLength] = 0x80;
            for (int i = 0; i < 8; i++)
                paddedData[totalLength - 1 - i] = (byte)(bitLen >> (i * 8));

            for (int i = 0; i < totalLength; i += 64)
                SHA256Transform(state, paddedData, i);

            // 大端输出 state[0..7]
            byte[] output = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                int pos = i * 4;
                output[pos] = (byte)(state[i] >> 24);
                output[pos + 1] = (byte)(state[i] >> 16);
                output[pos + 2] = (byte)(state[i] >> 8);
                output[pos + 3] = (byte)(state[i]);
            }
            return output;
        }

        #endregion

        #region 公共接口

        /// <summary>
        /// 单次哈希（使用IV1）
        /// </summary>
        /// <param name="data">输入数据</param>
        /// <returns>32字节哈希值</returns>
        public static byte[] HashOnce(byte[] data)
        {
            return CustomSHA256Hash(data, IV1);
        }

        /// <summary>
        /// 单次哈希（使用IV1，字符串输入）
        /// </summary>
        /// <param name="input">输入字符串（UTF-8编码）</param>
        /// <returns>十六进制哈希字符串（小写）</returns>
        public static string HashOnceString(string input)
        {
            byte[] data = Encoding.UTF8.GetBytes(input);
            byte[] hash = HashOnce(data);
            return BytesToHex(hash);
        }

        /// <summary>
        /// 双重哈希（先用IV1，再用IV2）
        /// </summary>
        /// <param name="data">输入数据</param>
        /// <returns>32字节哈希值</returns>
        public static byte[] DoubleHash(byte[] data)
        {
            byte[] firstHash = CustomSHA256Hash(data, IV1);
            byte[] secondHash = CustomSHA256Hash(firstHash, IV2);
            return secondHash;
        }

        /// <summary>
        /// 双重哈希（字符串输入）
        /// </summary>
        /// <param name="input">输入字符串（UTF-8编码）</param>
        /// <returns>十六进制哈希字符串（小写）</returns>
        public static string DoubleHashString(string input)
        {
            byte[] data = Encoding.UTF8.GetBytes(input);
            byte[] hash = DoubleHash(data);
            return BytesToHex(hash);
        }

        #endregion
    }
}
