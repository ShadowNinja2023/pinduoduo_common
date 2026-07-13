using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib.Crypto.Taobao
{
    public enum SecondaryEncType
    {
        None,       // 无二次加密
        Tea,        // 标准 TEA_ENC_KEYS 集合
        Bb98,       // bb98 交叉引用 TEA
        E0a1,       // e0a1_b1b2 TEA/XTEA 变体
    }

    public class DetectItem
    {
        public string DetectId;   // 4 字符 hex, 如 "ba2e"
        public string PolicyId;   // 4 字符 hex, 如 "b078"
        public string Value;      // 明文值 (可打印 ASCII 或 latin1)
        public byte[] BinaryValue; // 二进制明文 (用于 e0a1 等非文本检测项, 优先于 Value)
        public bool SkipVigenere; // true = 跳过 Vigenere 编码 (field 中无 marker, 直接写入)
        public SecondaryEncType SecondaryEnc; // 二次加密类型 (Encoder 自动执行对应的 TEA 加密)
    }
}
