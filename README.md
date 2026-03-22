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
└── Crypto/
    └── AntiTokenCrypto.cs     # 加密模块（预留）

TestConcole/                   # 控制台测试项目
└── Program.cs
```

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
