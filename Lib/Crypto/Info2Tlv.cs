using System;
using System.Collections.Generic;
using System.Text;

namespace PddLib.Crypto
{
    /// <summary>
    /// info2 (2af anti-token) 的 TLV 明文帧解析/构造。
    ///
    /// 帧布局:
    ///   [4B magic = 01 00 00 00]
    ///   [u16-BE totalLen]              // = 后续所有条目字节数
    ///   条目* :
    ///     [u16-BE entryLen]            // = 2 + value.Length (即 group+index+value)
    ///     [u8 group]                   // 样本恒为 0x01
    ///     [u8 index]                   // 0x01,0x02,... 顺序递增
    ///     [value(entryLen-2)]
    ///
    /// value 内层编码 (随字段而异):
    ///   - 字符串/字节:  [u8 innerLen][data]    (data 长度 = innerLen, innerLen ≤ 255)
    ///   - 整数:         [u8 byteLen][大端字节]  (如 1/4/8 字节)
    ///   - 空:           [00]
    ///   - 复合(如 idx=0x1d kernel /proc/version, 长度>255): 原始字节, 见 PutRaw
    /// </summary>
    public class Info2Tlv
    {
        public static readonly byte[] Magic = { 0x01, 0x00, 0x00, 0x00 };

        public class Entry
        {
            public byte Group;
            public byte Index;
            public byte[] Value = Array.Empty<byte>();   // 不含 entryLen/group/index
        }

        public List<Entry> Entries { get; } = new();

        // ==================== 解析 ====================

        /// <summary>解析 TLV 明文帧为条目列表。</summary>
        public static Info2Tlv Parse(byte[] raw)
        {
            var t = new Info2Tlv();
            if (raw.Length < 6) throw new ArgumentException("TLV 太短");
            // magic + totalLen 校验 (不强制, 仅读取)
            int total = (raw[4] << 8) | raw[5];
            int i = 6;
            int end = Math.Min(raw.Length, 6 + total);
            while (i + 2 <= end)
            {
                int entryLen = (raw[i] << 8) | raw[i + 1];
                if (entryLen < 2 || i + 2 + entryLen > raw.Length) break;
                var e = new Entry
                {
                    Group = raw[i + 2],
                    Index = raw[i + 3],
                    Value = raw[(i + 4)..(i + 2 + entryLen)]
                };
                t.Entries.Add(e);
                i += 2 + entryLen;
            }
            return t;
        }

        // ==================== 构造 ====================

        /// <summary>序列化为完整 TLV 明文帧 (magic + totalLen + 条目)。</summary>
        public byte[] Build()
        {
            using var body = new System.IO.MemoryStream();
            foreach (var e in Entries)
            {
                int entryLen = 2 + e.Value.Length;
                body.WriteByte((byte)(entryLen >> 8));
                body.WriteByte((byte)(entryLen & 0xFF));
                body.WriteByte(e.Group);
                body.WriteByte(e.Index);
                body.Write(e.Value, 0, e.Value.Length);
            }
            byte[] bodyBytes = body.ToArray();

            using var ms = new System.IO.MemoryStream();
            ms.Write(Magic, 0, 4);
            ms.WriteByte((byte)(bodyBytes.Length >> 8));
            ms.WriteByte((byte)(bodyBytes.Length & 0xFF));
            ms.Write(bodyBytes, 0, bodyBytes.Length);
            return ms.ToArray();
        }

        // ==================== 添加字段 (value 内层编码) ====================

        /// <summary>追加原始 value (调用方自行编码 value 内层), group 默认 0x01。</summary>
        public Info2Tlv PutRaw(byte index, byte[] value, byte group = 0x01)
        {
            Entries.Add(new Entry { Group = group, Index = index, Value = value });
            return this;
        }

        /// <summary>字符串字段: value = [u8 len][utf8]。len 必须 ≤255。</summary>
        public Info2Tlv PutString(byte index, string s, byte group = 0x01)
        {
            byte[] data = Encoding.UTF8.GetBytes(s ?? "");
            if (data.Length > 255) throw new ArgumentException($"字符串超 255 字节({data.Length}), 需用 PutRaw: idx=0x{index:x2}");
            var v = new byte[data.Length + 1];
            v[0] = (byte)data.Length;
            Array.Copy(data, 0, v, 1, data.Length);
            return PutRaw(index, v, group);
        }

        /// <summary>空字段: value = [00]。</summary>
        public Info2Tlv PutEmpty(byte index, byte group = 0x01) => PutRaw(index, new byte[] { 0x00 }, group);

        /// <summary>整数字段 (大端, 指定字节数): value = [u8 byteLen][大端字节]。</summary>
        public Info2Tlv PutIntBE(byte index, long value, int byteLen, byte group = 0x01)
        {
            var data = new byte[byteLen];
            for (int k = byteLen - 1; k >= 0; k--) { data[k] = (byte)(value & 0xFF); value >>= 8; }
            var v = new byte[byteLen + 1];
            v[0] = (byte)byteLen;
            Array.Copy(data, 0, v, 1, byteLen);
            return PutRaw(index, v, group);
        }

        public Info2Tlv PutU8(byte index, int value, byte group = 0x01) => PutIntBE(index, value & 0xFF, 1, group);
        public Info2Tlv PutU32(byte index, long value, byte group = 0x01) => PutIntBE(index, value, 4, group);
        public Info2Tlv PutU64(byte index, long value, byte group = 0x01) => PutIntBE(index, value, 8, group);

        /// <summary>字节数组字段: value = [u8 len][bytes]。</summary>
        public Info2Tlv PutBytes(byte index, byte[] data, byte group = 0x01)
        {
            if (data.Length > 255) throw new ArgumentException("字节数组超 255, 需用 PutRaw");
            var v = new byte[data.Length + 1];
            v[0] = (byte)data.Length;
            Array.Copy(data, 0, v, 1, data.Length);
            return PutRaw(index, v, group);
        }

        // ==================== 取字段值 (解析后读取内层) ====================

        public Entry? Get(byte index) => Entries.Find(e => e.Index == index);

        /// <summary>取字符串内层 (value = [u8 len][utf8])。</summary>
        public string GetString(byte index)
        {
            var e = Get(index);
            if (e == null || e.Value.Length < 1) return "";
            int len = e.Value[0];
            return Encoding.UTF8.GetString(e.Value, 1, Math.Min(len, e.Value.Length - 1));
        }
    }
}
