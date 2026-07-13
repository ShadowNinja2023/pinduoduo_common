import struct, sys
# 清除 PE 的 IMAGE_DLLCHARACTERISTICS_GUARD_CF (0x4000), 关闭进程 CFG
path = sys.argv[1]
d = bytearray(open(path, 'rb').read())
e = struct.unpack_from('<I', d, 0x3C)[0]
opt = e + 0x18
dc_off = opt + 0x46
dc = struct.unpack_from('<H', d, dc_off)[0]
if dc & 0x4000:
    struct.pack_into('<H', d, dc_off, dc & ~0x4000)
    open(path, 'wb').write(d)
    print(f"cleared GUARD_CF: 0x{dc:04x} -> 0x{dc & ~0x4000:04x}  [{path}]")
else:
    print(f"already no GUARD_CF (0x{dc:04x}) [{path}]")
