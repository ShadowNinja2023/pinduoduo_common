using Org.BouncyCastle.Utilities.Zlib;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PddLib.Crypto.Taobao
{
    public class Zlib
    {

        public static byte[] Decompress(byte[] data)
        {
            using (MemoryStream outputStream = new MemoryStream(0))
            {
                using (MemoryStream dataStream = new MemoryStream(data))
                {
                    using (ZInputStream inputStream = new ZInputStream(dataStream))
                    {
                        inputStream.CopyTo(outputStream);
                        return outputStream.ToArray();
                    }
                }
            }

        }

        public static byte[] Compress(byte[] data)
        {
            using (MemoryStream outputStream = new MemoryStream(0))
            {
                using (MemoryStream dataStream = new MemoryStream(data))
                {
                    using (ZOutputStream compressStream = new ZOutputStream(outputStream, JZlib.Z_DEFAULT_COMPRESSION))
                    {
                        dataStream.CopyTo(compressStream);
                    }

                }
                return outputStream.ToArray();
            }

        }
    }
}
