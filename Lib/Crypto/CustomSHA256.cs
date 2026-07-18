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
        /// 自定义IV1（第1轮哈希使用，小端字节序）
        /// 对应uint值: [0x8FF580D7, 0x0DE03D94, 0x893B5804, 0x17C0980F,
        ///             0x5B2A4684, 0x4ED07AAA, 0xA2042F7B, 0x0AB824FA]
        /// </summary>
        private static readonly byte[] IV1_BYTES = new byte[]
        {
            0xD7, 0x80, 0xF5, 0x8F, 0x94, 0x3D, 0xE0, 0x0D,
            0x04, 0x58, 0x3B, 0x89, 0x0F, 0x98, 0xC0, 0x17,
            0x84, 0x46, 0x2A, 0x5B, 0xAA, 0x7A, 0xD0, 0x4E,
            0x7B, 0x2F, 0x04, 0xA2, 0xFA, 0x24, 0xB8, 0x0A
        };

        /// <summary>
        /// 自定义IV2（第2轮哈希使用，小端字节序）
        /// 对应uint值: [0x2FA5793A, 0x8121E75E, 0x5BFC9F6A, 0x41EBF1BB,
        ///             0x2B478621, 0x83AD6FF6, 0x0ABE0279, 0x3CA23BF9]
        /// </summary>
        private static readonly byte[] IV2_BYTES = new byte[]
        {
            0x3A, 0x79, 0xA5, 0x2F, 0x5E, 0xE7, 0x21, 0x81,
            0x6A, 0x9F, 0xFC, 0x5B, 0xBB, 0xF1, 0xEB, 0x41,
            0x21, 0x86, 0x47, 0x2B, 0xF6, 0x6F, 0xAD, 0x83,
            0x79, 0x02, 0xBE, 0x0A, 0xF9, 0x3B, 0xA2, 0x3C
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
        /// 单次自定义SHA-256哈希
        /// </summary>
        /// <param name="data">输入数据</param>
        /// <param name="ivBytes">初始向量（32字节，小端格式）</param>
        /// <returns>32字节哈希值</returns>
        private static byte[] CustomSHA256Hash(byte[] data, byte[] ivBytes)
        {
            // 从小端字节解析IV到uint数组
            uint[] state = new uint[8];
            for (int i = 0; i < 8; i++)
            {
                int pos = i * 4;
                state[i] = ((uint)ivBytes[pos]) |
                          ((uint)ivBytes[pos + 1] << 8) |
                          ((uint)ivBytes[pos + 2] << 16) |
                          ((uint)ivBytes[pos + 3] << 24);
            }

            // ⚠️ 关键修改：长度字段 = (实际长度 + 64) * 8
            // 标准SHA-256使用: len(data) * 8
            // 自定义算法使用: (len(data) + 64) * 8
            ulong messageLengthBits = (ulong)(data.Length + 64) * 8;

            // SHA-256 Padding
            int originalLength = data.Length;
            int paddingLength = (64 - ((originalLength + 9) % 64)) % 64;
            int totalLength = originalLength + 1 + paddingLength + 8;

            byte[] paddedData = new byte[totalLength];

            // 复制原始数据
            Array.Copy(data, 0, paddedData, 0, originalLength);

            // 添加0x80
            paddedData[originalLength] = 0x80;

            // 填充0（paddingLength个字节默认为0）

            // 添加长度字段（大端序，最后8字节）
            for (int i = 0; i < 8; i++)
            {
                paddedData[totalLength - 1 - i] = (byte)(messageLengthBits >> (i * 8));
            }

            // 处理所有64字节块
            for (int i = 0; i < totalLength; i += 64)
            {
                SHA256Transform(state, paddedData, i);
            }

            // 输出转换：模拟ARM小端存储后的大端输出
            // 步骤1: 将state按小端格式存入"内存"
            byte[] memory = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                int pos = i * 4;
                memory[pos] = (byte)(state[i]);
                memory[pos + 1] = (byte)(state[i] >> 8);
                memory[pos + 2] = (byte)(state[i] >> 16);
                memory[pos + 3] = (byte)(state[i] >> 24);
            }

            // 步骤2: 按小端格式读回
            uint[] stateReloaded = new uint[8];
            for (int i = 0; i < 8; i++)
            {
                int pos = i * 4;
                stateReloaded[i] = ((uint)memory[pos]) |
                                  ((uint)memory[pos + 1] << 8) |
                                  ((uint)memory[pos + 2] << 16) |
                                  ((uint)memory[pos + 3] << 24);
            }

            // 步骤3: 按大端格式输出
            byte[] output = new byte[32];
            for (int i = 0; i < 8; i++)
            {
                int pos = i * 4;
                output[pos] = (byte)(stateReloaded[i] >> 24);
                output[pos + 1] = (byte)(stateReloaded[i] >> 16);
                output[pos + 2] = (byte)(stateReloaded[i] >> 8);
                output[pos + 3] = (byte)(stateReloaded[i]);
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
            return CustomSHA256Hash(data, IV1_BYTES);
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
            byte[] firstHash = CustomSHA256Hash(data, IV1_BYTES);
            byte[] secondHash = CustomSHA256Hash(firstHash, IV2_BYTES);
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
