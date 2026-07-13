using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib.Crypto.Taobao
{
    internal class Algorithm
    {
        internal static byte[] DecodeByHeaders4(byte[] data, byte[] header)
        {
            var result = new byte[data.Length];
            if (header.Length != 4)
            {
                throw new ArgumentException("xor header length must be 4");
            }

            for (var i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ header[(i + 2) % 4]);
            }

            return result;
        }

        internal static byte[] DecodeByBox(byte[] data)
        {
            var key = "64a7f9e9b0d32ca67eb72f86ec60cc437730e2a1";
            var keyBytes = key.FromHexString();

            if (data.Length % 20 != 0)
            {
                throw new Exception("长度不是20的倍数");
            }

            List<byte> resultBytes = new List<byte>();

            for (var i = 0; i < data.Length / 20; i++)
            {
                var temp = data.Skip(i * 20).Take(20).ToArray();
                var temp2 = new byte[20];
                for (var i1 = 0; i1 < temp.Length; i1++)
                {
                    temp2[i1] = (byte)((int)temp[i1] ^ (int)keyBytes[i1]);
                }

                //进行行列移位
                //每4个字节为一行
                var box = new List<byte[]>();
                for (var i1 = 0; i1 < 5; i1++)
                {
                    box.Add(temp2.Skip(i1 * 4).Take(4).ToArray());
                }

                box = BoxColumnMoveDown(box, 3, 1);

                var output = BoxMoveRight(box, 9);

                resultBytes.AddRange(output);

            }

            var final = RemovePadding(resultBytes.ToArray());

            return final;
        }

        internal static byte[] DecodeByBox24(byte[] data)
        {
            var keyBytes = "3c24feee1e127f770f89bf3b87c4df9d43e2efce21f177e7".FromHexString();

            if (data.Length % 24 != 0)
            {
                throw new Exception("长度不是24的倍数");
            }

            List<byte> resultBytes = new List<byte>();

            for (var i = 0; i < data.Length / 24; i++)
            {
                var temp = data.Skip(i * 24).Take(24).ToArray();
                var temp2 = new byte[24];
                for (var i1 = 0; i1 < temp.Length; i1++)
                {
                    temp2[i1] = (byte)((int)temp[i1] ^ (int)keyBytes[i1]);
                }

                //进行行列移位
                //每4个字节为一行
                var box = new List<byte[]>();
                for (var i1 = 0; i1 < 6; i1++)
                {
                    box.Add(temp2.Skip(i1 * 4).Take(4).ToArray());
                }

                box = BoxColumnMoveUp(box, 0, 2);

                var output = BoxMoveRight(box, 3);

                resultBytes.AddRange(output);
            }

            var final = RemovePadding(resultBytes.ToArray());

            return final;
        }

        internal static List<List<byte[]>> Decode18ByBox24(byte[] data)
        {
            var keyBytes = "a0811551d0c08a286860451434b0220a1a5811050dac8802".FromHexString();

            if (data.Length % 24 != 0)
            {
                throw new Exception("长度不是24的倍数");
            }

            List<List<byte[]>> boxContainer = new List<List<byte[]>>();

            for (var i = 0; i < data.Length / 24; i++)
            {
                var temp = data.Skip(i * 24).Take(24).ToArray();
                var temp2 = new byte[24];
                for (var i1 = 0; i1 < temp.Length; i1++)
                {
                    var b = (byte)((int)temp[i1] ^ (int)keyBytes[i1]);
                    temp2[i1] = b;
                }

                //进行行列移位
                //每4个字节为一行
                var box = new List<byte[]>();
                for (var i1 = 0; i1 < 6; i1++)
                {
                    box.Add(temp2.Skip(i1 * 4).Take(4).ToArray());
                }

                boxContainer.Add(box);
            }

            return boxContainer;
        }

        internal static List<List<byte[]>> Decode15ByBox16(byte[] data)
        {
            var keyBytes = "f23c1772599e03b98934865c641a4b2e".FromHexString();

            if (data.Length % 16 != 0)
            {
                throw new Exception("长度不是16的倍数");
            }

            List<List<byte[]>> boxContainer = new List<List<byte[]>>();

            for (var i = 0; i < data.Length / 16; i++)
            {
                var temp = data.Skip(i * 16).Take(16).ToArray();
                var temp2 = new byte[16];
                for (var i1 = 0; i1 < temp.Length; i1++)
                {
                    var b = (byte)((int)temp[i1] ^ (int)keyBytes[i1]);
                    temp2[i1] = b;
                }

                //每4个字节为一行
                var box = new List<byte[]>();
                for (var i1 = 0; i1 < 4; i1++)
                {
                    box.Add(temp2.Skip(i1 * 4).Take(4).ToArray());
                }

                boxContainer.Add(box);
            }

            return boxContainer;
        }

        internal static List<List<byte[]>> Decode14ByBox16(byte[] data)
        {
            var keyBytes = "b6a0c62d7e2723c4188b3771f25d0d7f".FromHexString();

            if (data.Length % 16 != 0)
            {
                throw new Exception("长度不是16的倍数");
            }

            List<List<byte[]>> boxContainer = new List<List<byte[]>>();

            for (var i = 0; i < data.Length / 16; i++)
            {
                var temp = data.Skip(i * 16).Take(16).ToArray();
                var temp2 = new byte[16];
                for (var i1 = 0; i1 < temp.Length; i1++)
                {
                    var b = (byte)((int)temp[i1] ^ (int)keyBytes[i1]);
                    temp2[i1] = b;
                }

                //每4个字节为一行
                var box = new List<byte[]>();
                for (var i1 = 0; i1 < 4; i1++)
                {
                    box.Add(temp2.Skip(i1 * 4).Take(4).ToArray());
                }

                boxContainer.Add(box);
            }

            return boxContainer;
        }

        internal static byte[] Encode14ByBox16(byte[] data)
        {
            var keyBytes = "b6a0c62d7e2723c4188b3771f25d0d7f".FromHexString();

            if (data.Length % 16 != 0)
            {
                throw new Exception("长度不是16的倍数");
            }

            List<byte> result = new List<byte>();

            for (var i = 0; i < data.Length / 16; i++)
            {
                var temp = data.Skip(i * 16).Take(16).ToArray();
                var temp2 = new byte[16];
                for (var i1 = 0; i1 < temp.Length; i1++)
                {
                    var b = (byte)((int)temp[i1] ^ (int)keyBytes[i1]);
                    temp2[i1] = b;
                }
                result.AddRange(temp2);
            }

            return result.ToArray();
        }



        internal static List<byte[]> ReverseNumBorrow(List<byte[]> box)
        {
            var result = new List<byte[]>();
            for (var lineNumber = 0; lineNumber < box.Count; lineNumber++)
            {
                var newLine = new byte[box[lineNumber].Length];
                var line = box[lineNumber];
                for (var i = 0; i < line.Length; i++)
                {
                    var myLowBit = line[i] & 0x3;
                    //如果是前3个字节，下家都是右边下一个，如果是最后一个字节，找到下移第三行的第一个字节
                    var nextBit = 0;
                    if (i == line.Length - 1)
                    {
                        nextBit = box[(lineNumber + 3) % box.Count][0];
                    }
                    else
                    {
                        nextBit = line[i + 1];
                    }

                    var nextLowBit = nextBit & 0x3;

                    //自身lowbit要还给上家，下家的lowbit要还给自己
                    newLine[i] = (byte)(line[i] - myLowBit + nextLowBit);
                }
                result.Add(newLine);
            }


            return result;
        }

        internal static List<byte[]> ReverseNumBorrow15(List<byte[]> box)
        {
            var result = new List<byte[]>();
            for (var lineNumber = 0; lineNumber < box.Count; lineNumber++)
            {
                var newLine = new byte[box[lineNumber].Length];
                var line = box[lineNumber];
                for (var i = 0; i < line.Length; i++)
                {
                    var nextBit = 0;
                    if (i == line.Length - 1)
                    {
                        nextBit = box[(lineNumber + 2) % box.Count][0];
                    }
                    else
                    {
                        nextBit = line[i + 1];
                    }
                    //获取自己低位+找下家要高位
                    var decodeBit = (line[i] >> 4) + ((nextBit & 0xf) << 4);
                    newLine[i] = (byte)decodeBit;
                }
                result.Add(newLine);
            }

            return result;
        }

        internal static byte[] ReverseNumBox14(List<byte[]> box)
        {
            var boxMoved = BoxColumnMoveDown(box, 0, 1);
            boxMoved = BoxColumnMoveDown(boxMoved, 1, 1);
            boxMoved = BoxColumnMoveDown(boxMoved, 2, 1);
            boxMoved = BoxColumnMoveUp(boxMoved, 3, 1);
            var finalBox = ShiftRowRight(boxMoved, 1);
            //顺序还原后，需要处理右移和数字的借位，规则应该是每个数字的低位 = 索引前一位的高位
            var final = ReverseNumBorrow14(finalBox);

            return final.SelectMany(x => x).ToArray();
        }

        private static List<byte[]> ReverseNumBorrow14(List<byte[]> box)
        {
            //直接按顺序平坦化就行
            var result = new List<byte[]>();

            for (var lineNumber = 0; lineNumber < box.Count; lineNumber++)
            {
                var newLine = new byte[box[lineNumber].Length];
                var line = box[lineNumber];
                for (var i = 0; i < line.Length; i++)
                {
                    //下家的低位是我的高位 同理我的低位是上家的高位，但是因为右移1 所以不用额外处理，只需要找下家拿低位放自己高位即可
                    //应该跟15规则一样，下两行的首位
                    var nextBit = 0;
                    if (i == line.Length - 1)
                    {
                        nextBit = box[(lineNumber + 2) % box.Count][0];
                    }
                    else
                    {
                        nextBit = line[i + 1];
                    }
                    newLine[i] = (byte)((line[i] >> 1) + ((nextBit & 1) << 7));
                }
                result.Add(newLine);
            }

            return result;
        }

        internal static byte[] GetNumBox14(byte[] data)
        {
            //16位分割成盒子，处理移位和借数字，最后行列转移
            data = AddPadding(data, 16);

            List<List<byte[]>> boxContainer = new List<List<byte[]>>();

            for (var i = 0; i < data.Length / 16; i++)
            {
                var temp = data.Skip(i * 16).Take(16).ToArray();

                //每4个字节为一行
                var box = new List<byte[]>();
                for (var i1 = 0; i1 < 4; i1++)
                {
                    box.Add(temp.Skip(i1 * 4).Take(4).ToArray());
                }
                boxContainer.Add(NumBorrow14(box));
            }

            var result = new List<byte>();
            //再处理行列移位
            foreach (var box in boxContainer)
            {
                var boxMoved = ShiftRowLeft(box, 1);
                boxMoved = BoxColumnMoveDown(boxMoved, 3, 1);
                boxMoved = BoxColumnMoveUp(boxMoved, 2, 1);
                boxMoved = BoxColumnMoveUp(boxMoved, 1, 1);
                boxMoved = BoxColumnMoveUp(boxMoved, 0, 1);
                result.AddRange(boxMoved.SelectMany(x => x));
            }


            return result.ToArray();
        }

        public static List<byte[]> NumBorrow14(List<byte[]> box)
        {
            //算法核心就是把自己的高位给下家的低位，然后自己的低位放到自己的高位
            var result = new List<byte[]>();
            //先填充字节，用来承载后面的highbit
            for (var i = 0; i < box.Count; i++)
            {
                result.Add(new byte[box[i].Length]);
            }

            for (var lineNumber = 0; lineNumber < box.Count; lineNumber++)
            {
                var newLine = result[lineNumber];
                var line = box[lineNumber];
                for (var i = 0; i < line.Length; i++)
                {
                    //14是左移1  15是左移4
                    var myHighBit = line[i] >> 7;
                    var myLowBit = line[i] << 1 & 0xff;

                    //存自己的低位，给下家高位
                    newLine[i] += (byte)myLowBit;

                    //把自己的高位给下家
                    if (i == line.Length - 1)
                    {
                        result[(lineNumber + 2) % box.Count][0] += (byte)myHighBit;
                    }
                    else
                    {
                        newLine[i + 1] += (byte)myHighBit;
                    }
                }
            }

            return result;
        }


        internal static byte RightShiftAndWrap(byte num, int shiftBits)
        {
            int mask = (1 << shiftBits) - 1;  // 创建一个掩码，用来获取低位丢弃的部分
            int droppedBits = num & mask;     // 获取被丢弃的位

            num >>= shiftBits;                // 右移操作
            droppedBits <<= 8 - shiftBits;  // 将丢弃的位移动到高位

            if (droppedBits > 0)
            {
                //Log.Write("fdsaf");
            }

            return (byte)(num | droppedBits);  // 合并右移后的结果和移动到高位的丢弃位
        }

        internal static List<byte[]> BoxColumnMoveUp(List<byte[]> box, int colomnIndex, int moveStep)
        {
            var outputBox = new List<byte[]>();
            foreach (var item in box)
            {
                byte[] byteArrayCopy = new byte[item.Length];
                item.CopyTo(byteArrayCopy, 0);
                outputBox.Add(byteArrayCopy);
            }
            for (var i = 0; i < box.Count; i++)
            {
                var item = box[i];
                var targetIndex = (i - moveStep + box.Count) % box.Count;

                outputBox[targetIndex][colomnIndex] = item[colomnIndex];
            }

            return outputBox;
        }

        internal static List<byte[]> BoxColumnMoveDown(List<byte[]> box, int colomnIndex, int moveStep)
        {
            var outputBox = new List<byte[]>();
            foreach (var item in box)
            {
                byte[] byteArrayCopy = new byte[item.Length];
                item.CopyTo(byteArrayCopy, 0);
                outputBox.Add(byteArrayCopy);
            }

            for (var i = 0; i < box.Count; i++)
            {
                var item = box[i];
                var targetIndex = (i + moveStep) % box.Count;

                outputBox[targetIndex][colomnIndex] = item[colomnIndex];
            }

            return outputBox;

        }

        static List<byte[]> ShiftRowRight(List<byte[]> box, int step)
        {
            List<byte[]> result = new List<byte[]>();

            foreach (var line in box)
            {
                var newBytes = new byte[line.Length];
                //每一行右移动step步数
                for (var i = 0; i < line.Length; i++)
                {
                    //右移1时 line[0] = newBytes[1]
                    var index = (i + step) % line.Length;
                    newBytes[index] = line[i];
                }

                result.Add(newBytes);
            }

            return result;
        }

        static List<byte[]> ShiftRowLeft(List<byte[]> box, int step)
        {
            List<byte[]> result = new List<byte[]>();

            foreach (var line in box)
            {
                var newBytes = new byte[line.Length];
                for (var i = 0; i < line.Length; i++)
                {
                    var index = (i - step + line.Length) % line.Length;
                    newBytes[index] = line[i];
                }

                result.Add(newBytes);
            }

            return result;
        }

        internal static byte[] BoxMoveRight(List<byte[]> box, int moveStep)
        {
            //平坦化为一行，再进行右移动
            int totalLength = box.Sum(a => a.Length);

            // 创建一个足够大的数组来容纳所有元素
            byte[] flattenedArray = new byte[totalLength];

            // 复制每个子数组到结果数组
            int currentPosition = 0;
            foreach (byte[] array in box)
            {
                Array.Copy(array, 0, flattenedArray, currentPosition, array.Length);
                currentPosition += array.Length;
            }

            var output = new byte[flattenedArray.Length];


            for (var i = 0; i < flattenedArray.Length; i++)
            {
                var item = flattenedArray[i];
                var targetIndex = (i + moveStep) % flattenedArray.Length;

                output[targetIndex] = item;
            }


            return output;
        }

        internal static byte[] RemovePadding(byte[] data)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentException("Data cannot be empty");

            // 获取最后一个字节，它表示填充长度
            byte paddingLength = data[data.Length - 1];

            // 检查填充长度是否有效
            if (paddingLength > data.Length || paddingLength == 0)
                throw new ArgumentException("Invalid padding length");

            // 确认所有填充字节都符合预期
            for (int i = data.Length - paddingLength; i < data.Length; i++)
            {
                if (data[i] != paddingLength)
                    throw new ArgumentException("Invalid padding content");
            }

            // 创建一个新数组，长度为原始数据长度减去填充长度
            byte[] trimmedData = new byte[data.Length - paddingLength];
            Array.Copy(data, 0, trimmedData, 0, trimmedData.Length);

            return trimmedData;
        }

        internal static int ConvertHexLittleEndianToInt(string hex)
        {
            // 确保字符串长度为偶数
            if (hex.Length % 2 != 0) throw new ArgumentException("Hexadecimal string length must be even.");

            // 将字符串分割成两个字符的组，并以反向顺序重新组合
            string reOrderedHex = "";
            for (int i = hex.Length - 2; i >= 0; i -= 2)
            {
                reOrderedHex += hex.Substring(i, 2);
            }

            // 将重新排序后的十六进制字符串转换为十进制
            return int.Parse(reOrderedHex, System.Globalization.NumberStyles.HexNumber);
        }

        public static byte[] EncodeByBox16(byte[] data)
        {
            var keyBytes = "64a7f9e9b0d32ca67eb72f86ec60cc437730e2a1".FromHexString();

            // Add padding to ensure the length of data is a multiple of 20
            data = AddPadding(data, 20);

            List<byte> resultBytes = new List<byte>();

            for (var i = 0; i < data.Length / 20; i++)
            {
                var temp = data.Skip(i * 20).Take(20).ToArray();
                temp = BoxMoveLeft(temp, 9);
                // Undo the row shifts first
                var box = new List<byte[]>();
                for (var i1 = 0; i1 < 5; i1++)
                {
                    box.Add(temp.Skip(i1 * 4).Take(4).ToArray());
                }

                // Reverse the column and row shifts
                box = BoxColumnMoveUp(box, 3, 1);

                var temp2 = box.SelectMany(x => x).ToArray();

                // Flatten the box back to byte array before XOR

                // XOR with the key
                for (var i1 = 0; i1 < temp2.Length; i1++)
                {
                    temp2[i1] = (byte)(temp2[i1] ^ keyBytes[i1]);
                }

                resultBytes.AddRange(temp2);
            }

            return resultBytes.ToArray();
        }

        private static byte[] EncodeByBox24(byte[] data)
        {
            var keyBytes = "3c24feee1e127f770f89bf3b87c4df9d43e2efce21f177e7".FromHexString();

            data = AddPadding(data, 24);

            List<byte> resultBytes = new List<byte>();

            for (var i = 0; i < data.Length / 24; i++)
            {
                var temp = data.Skip(i * 24).Take(24).ToArray();
                temp = BoxMoveLeft(temp, 3);

                var box = new List<byte[]>();
                for (var i1 = 0; i1 < 6; i1++)
                {
                    box.Add(temp.Skip(i1 * 4).Take(4).ToArray());
                }

                box = BoxColumnMoveDown(box, 0, 2);
                var temp2 = box.SelectMany(x => x).ToArray();

                for (var i1 = 0; i1 < temp2.Length; i1++)
                {
                    temp2[i1] = (byte)((int)temp2[i1] ^ (int)keyBytes[i1]);
                }

                resultBytes.AddRange(temp2);
            }



            return resultBytes.ToArray();
        }

        private static byte[] Encode18ByBox24(byte[] data)
        {
            var keyBytes = "a0811551d0c08a286860451434b0220a1a5811050dac8802".FromHexString();

            if (data.Length % 24 != 0)
            {
                throw new Exception("长度不是24的倍数");
            }

            var result = new List<byte>();

            for (var i = 0; i < data.Length / 24; i++)
            {
                var temp = data.Skip(i * 24).Take(24).ToArray();
                var temp2 = new byte[24];
                for (var i1 = 0; i1 < temp.Length; i1++)
                {
                    temp2[i1] = (byte)((int)temp[i1] ^ (int)keyBytes[i1]);
                }

                result.AddRange(temp2);
            }

            return result.ToArray();
        }

        public static byte[] Encode15ByBox16(byte[] data)
        {
            var keyBytes = "f23c1772599e03b98934865c641a4b2e".FromHexString();

            if (data.Length % 16 != 0)
            {
                throw new Exception("长度不是16的倍数");
            }

            var result = new List<byte>();

            for (var i = 0; i < data.Length / 16; i++)
            {
                var temp = data.Skip(i * 16).Take(16).ToArray();
                var temp2 = new byte[16];
                for (var i1 = 0; i1 < temp.Length; i1++)
                {
                    temp2[i1] = (byte)((int)temp[i1] ^ (int)keyBytes[i1]);
                }
                result.AddRange(temp2);
            }

            return result.ToArray();
        }

        internal static byte[] EncodeByHeaders4(byte[] data, byte[] header)
        {
            var result = new byte[data.Length];
            if (header.Length != 4)
            {
                throw new ArgumentException("xor header length must be 4");
            }

            for (var i = 0; i < data.Length; i++)
            {
                result[i] = (byte)(data[i] ^ header[(i + 2) % 4]);
            }

            return result;
        }

        private static List<byte[]> NumBorrow(List<byte[]> box)
        {
            //这算法核心就每个字节是把自己的低位给下家

            var result = new List<byte[]>();
            //先填充字节，用来承载后面的lowbit
            for (var i = 0; i < box.Count; i++)
            {
                var newArray = new byte[box[i].Length];
                Array.Copy(box[i], newArray, box[i].Length);
                result.Add(newArray);
            }

            for (var lineNumber = 0; lineNumber < box.Count; lineNumber++)
            {
                var newLine = result[lineNumber];
                var line = box[lineNumber];
                for (var i = 0; i < line.Length; i++)
                {
                    //把lowbit给下家，但是不能递归，所以用新的Array result做承载,所有lowbit判断都以原来的值为依据
                    var myLowBit = line[i] & 0x3;

                    //减去自己的lowbit
                    newLine[i] -= (byte)myLowBit;

                    //找到下家，加上lowbit
                    if (i == line.Length - 1)
                    {
                        result[(lineNumber + 3) % box.Count][0] += (byte)myLowBit;
                    }
                    else
                    {
                        newLine[i + 1] += (byte)myLowBit;
                    }

                }
            }
            return result;
        }

        public static List<byte[]> NumBorrow15(List<byte[]> box)
        {
            //算法核心就是把自己的高位给下家的低位，然后自己的低位放到自己的高位
            var result = new List<byte[]>();
            //先填充字节，用来承载后面的highbit
            for (var i = 0; i < box.Count; i++)
            {
                result.Add(new byte[box[i].Length]);
            }

            for (var lineNumber = 0; lineNumber < box.Count; lineNumber++)
            {
                var newLine = result[lineNumber];
                var line = box[lineNumber];
                for (var i = 0; i < line.Length; i++)
                {
                    var myHighBit = line[i] >> 4;
                    var myLowBit = line[i] & 0xf;

                    //存自己的低位，给下家高位

                    newLine[i] += (byte)(myLowBit << 4);

                    //把自己的高位给下家
                    if (i == line.Length - 1)
                    {
                        result[(lineNumber + 2) % box.Count][0] += (byte)myHighBit;
                    }
                    else
                    {
                        newLine[i + 1] += (byte)myHighBit;
                    }
                }
            }

            return result;
        }

        private static byte LeftShiftAndWrap(byte num, int shiftBits)
        {
            int mask = (1 << 8 - shiftBits) - 1;  // Mask for the bits that will be dropped
            int droppedBits = num >> 8 - shiftBits & mask;  // Extract the bits to be dropped

            num <<= shiftBits;  // Perform the left shift
            droppedBits &= 0xFF;  // Ensure it's a valid byte
            return (byte)(num | droppedBits);  // Combine the shifted value and the wrapped bits
        }

        private static byte[] BoxMoveLeft(byte[] data, int moveStep)
        {

            byte[] output = new byte[data.Length];

            // Perform the left shift on the array
            for (var i = 0; i < data.Length; i++)
            {
                var item = data[i];
                // Calculate the new index considering the move to the left
                var targetIndex = (i - moveStep + data.Length) % data.Length;

                output[targetIndex] = item;
            }

            return output;
        }

        internal static byte[] AddPadding(byte[] data, int blockSize)
        {
            if (data == null || blockSize <= 0)
                throw new ArgumentException("Invalid input");

            // Calculate the padding length needed to make the data length a multiple of blockSize
            int paddingLength = blockSize - data.Length % blockSize;
            if (paddingLength == 0)
                paddingLength = blockSize;  // If no padding is needed, add a full block of padding

            // Create a new array with the size of the original data plus padding
            byte[] paddedData = new byte[data.Length + paddingLength];
            Array.Copy(data, 0, paddedData, 0, data.Length);

            // Fill the padding bytes with the padding length value
            for (int i = data.Length; i < paddedData.Length; i++)
            {
                paddedData[i] = (byte)paddingLength;
            }

            return paddedData;
        }

        internal static string ConvertIntToHexLittleEndian(int value)
        {
            // Convert the integer to a big-endian hexadecimal string
            string bigEndianHex = value.ToString("X8");

            // Rearrange the bytes to little-endian
            string littleEndianHex = "";
            for (int i = bigEndianHex.Length - 2; i >= 0; i -= 2)
            {
                littleEndianHex += bigEndianHex.Substring(i, 2);
            }

            return littleEndianHex;
        }


        internal static KeyValuePair<int, byte[]> ProcessDecode(byte[] group)
        {
            int encryptType = group[0];
            switch (encryptType)
            {
                case 0x14:
                    var headers = group.Skip(1).Take(4).ToArray();
                    var decode1 = Algorithm.DecodeByHeaders4(group.Skip(5).ToArray(), headers);
                    var decode2 = Algorithm.Decode14ByBox16(decode1);
                    var decodeResult = new List<byte>();
                    foreach (var box in decode2)
                    {
                        decodeResult.AddRange(Algorithm.ReverseNumBox14(box));
                    }
                    return new KeyValuePair<int, byte[]>(encryptType, Algorithm.RemovePadding(decodeResult.ToArray()));
                case 0x15:
                    headers = group.Skip(1).Take(4).ToArray();
                    decode1 = Algorithm.DecodeByHeaders4(group.Skip(5).ToArray(), headers);
                    //先xor
                    decode2 = Algorithm.Decode15ByBox16(decode1);

                    decodeResult = new List<byte>();
                    foreach (var box in decode2)
                    {
                        var newbox = Algorithm.ReverseNumBorrow15(box);
                        //直接平坦就是原文 15方式没有行移动
                        //先单独存方便debug
                        var array = newbox.SelectMany(x => x).ToArray();
                        decodeResult.AddRange(array);
                    }

                    return new KeyValuePair<int, byte[]>(encryptType, Algorithm.RemovePadding(decodeResult.ToArray()));
                case 0x16:
                    headers = group.Skip(1).Take(4).ToArray();
                    decode1 = Algorithm.DecodeByHeaders4(group.Skip(5).ToArray(), headers);
                    decode1 = Algorithm.DecodeByBox(decode1);
                    return new KeyValuePair<int, byte[]>(encryptType, decode1);
                case 0x17:
                    headers = group.Skip(1).Take(4).ToArray();
                    decode1 = Algorithm.DecodeByHeaders4(group.Skip(5).ToArray(), headers);
                    decode1 = Algorithm.DecodeByBox24(decode1);
                    return new KeyValuePair<int, byte[]>(encryptType, decode1);
                case 0x18:
                    headers = group.Skip(1).Take(4).ToArray();
                    decode1 = Algorithm.DecodeByHeaders4(group.Skip(5).ToArray(), headers);
                    decode2 = Algorithm.Decode18ByBox24(decode1);
                    decodeResult = new List<byte>();
                    foreach (var box in decode2)
                    {
                        var newbox = Algorithm.ReverseNumBorrow(box);
                        var decode3 = Algorithm.BoxMoveRight(newbox, 4);
                        var decode4 = new byte[decode3.Length];
                        for (var i = 0; i < decode3.Length; i++)
                        {
                            //右移还原
                            decode4[i] = Algorithm.RightShiftAndWrap(decode3[i], 2);
                        }
                        //先单独装方便查看结果
                        decodeResult.AddRange(decode4);
                    }

                    return new KeyValuePair<int, byte[]>(encryptType, Algorithm.RemovePadding(decodeResult.ToArray()));
                default:
                    throw new ArgumentException("Unknown encrypt type");

            }
        }

        internal static List<KeyValuePair<int, byte[]>> ProcessEncode(List<KeyValuePair<int, byte[]>> data)
        {
            var encodeList = new List<KeyValuePair<int, byte[]>>();

            foreach (var item in data)
            {
                var header = new byte[4];
                for (var i = 0; i < header.Length; i++)
                {
                    header[i] = (byte)new Random().Next(1, 0xff);
                }
                switch (item.Key)
                {
                    case 0x14:
                        var result = GetNumBox14(item.Value);
                        result = Encode14ByBox16(result);
                        result = EncodeByHeaders4(result, header);
                        encodeList.Add(new KeyValuePair<int, byte[]>(item.Key, header.Concat(result).ToArray()));
                        break;
                    case 0x15:
                        var encode = AddPadding(item.Value, 16);
                        var boxes = new List<byte[]>();
                        var tempEncodeResult = new List<byte>();
                        for (var i = 0; i < encode.Length / 16; i++)
                        {
                            boxes.Add(encode.Skip(i * 16).Take(16).ToArray());
                        }

                        foreach (var bytes in boxes)
                        {
                            //转小盒子
                            var box = new List<byte[]>();
                            for (var i = 0; i < bytes.Length / 4; i++)
                            {
                                box.Add(bytes.Skip(i * 4).Take(4).ToArray());
                            }
                            var newBox = NumBorrow15(box);
                            tempEncodeResult.AddRange(newBox.SelectMany(x => x).ToArray());
                        }
                        result = Encode15ByBox16(tempEncodeResult.ToArray());
                        result = EncodeByHeaders4(result, header);

                        encodeList.Add(new KeyValuePair<int, byte[]>(item.Key, header.Concat(result).ToArray()));
                        break;
                    case 0x16:
                        encode = EncodeByBox16(item.Value);
                        var encode1 = EncodeByHeaders4(encode, header);
                        encodeList.Add(new KeyValuePair<int, byte[]>(item.Key, header.Concat(encode1).ToArray()));
                        break;
                    case 0x17:
                        encode = EncodeByBox24(item.Value);
                        encode1 = EncodeByHeaders4(encode, header);
                        encodeList.Add(new KeyValuePair<int, byte[]>(item.Key, header.Concat(encode1).ToArray()));
                        break;
                    case 0x18:
                        tempEncodeResult = new List<byte>();
                        encode = AddPadding(item.Value, 24);
                        //拆成盒子
                        //24个一组
                        boxes = new List<byte[]>();
                        for (var i = 0; i < encode.Length / 24; i++)
                        {
                            boxes.Add(encode.Skip(i * 24).Take(24).ToArray());
                        }

                        foreach (var bytes in boxes)
                        {
                            encode1 = new byte[bytes.Length];
                            for (var i = 0; i < bytes.Length; i++)
                            {
                                encode1[i] = LeftShiftAndWrap(bytes[i], 2);
                            }
                            var encode2 = BoxMoveLeft(encode1, 4);

                            //4个一组，拆分成小盒子
                            var box = new List<byte[]>();
                            for (var i = 0; i < encode2.Length / 4; i++)
                            {
                                box.Add(encode2.Skip(i * 4).Take(4).ToArray());
                            }

                            var newBox = NumBorrow(box);

                            tempEncodeResult.AddRange(newBox.SelectMany(x => x).ToArray());
                        }

                        result = Encode18ByBox24(tempEncodeResult.ToArray());
                        result = EncodeByHeaders4(result, header);

                        encodeList.Add(new KeyValuePair<int, byte[]>(item.Key, header.Concat(result).ToArray()));
                        break;
                    default:
                        throw new ArgumentException("Unknown encrypt type");
                }
            }

            return encodeList;
        }
    }
}
