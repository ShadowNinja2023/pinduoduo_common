# PddCommon

C# 模拟拼多多 Android 端 HTTP 请求的基础库。

## 项目结构

```
Lib/                           # 核心库 (PddLib)
├── Android.cs                 # 主类，传入 Session + Device 构造实例，调用拼多多业务接口
├── Http.cs                    # 拼多多 HTTP 请求封装，处理公共参数与请求发送
├── BackendApi.cs              # 自有后端 API 调用封装（统一协议、鉴权）
├── Models/
│   ├── Device.cs              # 设备信息（品牌、型号、IMEI、Build 指纹等）
│   ├── Session.cs             # 会话信息（Uid、Uin、Acid、AccessToken 等）
│   ├── ApiResponse.cs         # 后端统一响应结构
│   └── GetDeviceResult.cs     # GetDevice 响应模型，支持解析为 Device/Session
├── Crypto/                    # 各字段加解密 codec
│   ├── AntiTokenCrypto.cs     # anti-token
│   ├── Info4Codec.cs          # DeviceNative.info4
│   ├── PddBodyCrypto.cs       # 报文体信封 (AES-128-CBC + RSA)
│   ├── XP1Codec.cs            # x-p1
│   ├── UserEnv2Codec.cs       # user_env2 (SE.ues, TEA-CBC 变体) —— extra 的外层容器
│   ├── WtpCodec.cs / PFieldsCodec.cs / P30Codec.cs / P49Codec.cs / P125Codec.cs
│   └── Extra/                 # ★ user_env2.extra (libdyncommon 1008 容器) 编解码
│       ├── Extra1008Codec.cs         # 容器分帧/标记/连续 XOR + DecryptAuto (两种变体)
│       ├── KeyTable.cs               # 硬编码 KeyTable 查表 (索引→KEY_8B) + Index3
│       ├── Seed.cs                   # seed = 4279|nonce|counter|KEY_8B
│       ├── IKeystreamGenerator.cs    # keystream 生成器抽象 (G 函数)
│       ├── StaticKeystreamGenerator.cs   # 喂预存 keystream (测试用)
│       ├── UnicornKeystreamGenerator.cs  # Unicorn 执行真实 G (生产用, 需 unicorn.dll)
│       ├── SnapshotLoader.cs         # unidbg 快照加载
│       ├── Extra1008Data.cs          # 数据目录定位
│       └── Native/Unicorn2.cs        # unicorn.dll P/Invoke
├── Data/Extra1008/            # extra 依赖数据 (keytable_region.bin + 快照 meta/so/stack, 随输出复制)
└── Register/                  # 设备 mock / 各报文 Builder

TestConcole/                   # 控制台测试项目
CodecTests/                    # codec 往返/正向逐字节验证 (含 extra 迁移冒烟)
```

## extra(1008) 解密

`user_env2.extra` 的 libdyncommon 1008 容器已实现端到端离线解密 (详见 `拼多多全量分析` 仓 §3.8(17)):
容器索引 → `KeyTable` 查表得 KEY_8B → `Seed` 组 seed → `IKeystreamGenerator` 生成 keystream → `Extra1008Codec` 连续 XOR。
编码(mock)方向: `Extra1008Codec.Encrypt` / `EncryptMock` (逆过程, 逐字节往返 == 原始容器)。
容器 `lenflag` = 两组 KEY 索引标记的定位指针 (`DecryptByLenflag` 确定性解码)。

**keystream 生成 (G 函数) 两种实现**:
- `StaticKeystreamGenerator` — 喂预存 keystream, `CodecTests` 用它验证容器编解码链路 (不依赖原生库, 29/29 PASS)。
- `UnicornKeystreamGenerator` — 执行真实 G, 对**任意 nonce/KEY** 生成 keystream。宿主项目 **`ExtraMock/`** 演示端到端 (解真机容器 / mock 任意 nonce/KEY / 逐字节往返, 4/4 PASS)。
  - `unicorn.dll` (win-x64) 在 `Lib/Native/`, 由 `Uc` 的 DllImport 解析器定位。
  - 宿主 exe 需关 CET (`<CETCompat>false>`) + 清 apphost GUARD_CF (post-build `_nocfg.py`, 需 python), 否则 Unicorn JIT 会 fastfail。

## 快速开始

```csharp
using PddLib;

// 1. 通过后端 API 获取设备
var api = new BackendApi("https://open-cdn.reverse-studio.com", "your_token");
var result = await api.GetDeviceAsync();          // 随机获取
// var result = await api.GetDeviceAsync("账号");  // 指定账号

// 2. 解析为强类型
var session = result.Results.ParseSession();
var device = result.Results.ParseDevice();

// 3. 创建 Android 实例，调用拼多多接口
var android = new Android(session, device);
var userInfo = await android.GetUserInfoAsync();
```

## 后端 API

详见 [docs/backend_api.md](docs/backend_api.md)

基础协议：`POST https://{host}/{服务名}/{方法名}?Token={令牌}`，统一响应 `{code, messages, results}`。

已实现接口：
- `PinDuoDuo/GetDevice` — 获取设备信息（支持指定账号或随机获取）

## 环境要求

- .NET 7.0
