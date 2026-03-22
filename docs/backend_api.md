# backend_dataapi 接口文档

## 请求规范

所有接口通过 RESTful 风格路由访问：

```
POST https://{host}/{服务名}/{方法名}?Token={自己令牌}
Content-Type: application/json

{请求体 JSON}
```

示例：
```
POST https://open-cdn.reverse-studio.com/Taobao/GetItemDetail?Token={自己令牌}
Content-Type: application/json

{"id":"123456"}
```

---

## 鉴权说明

- 非 DEBUG 模式下，所有接口均需传入有效 Token
- Token 通过 URL 参数 `Token` 传递
- Token 需预先存储于 Redis（Key 格式：`RepApp{Token}`，Value 为 token_id）
- Token 校验失败时返回 `code: "-101"`

**令牌非法响应示例：**
```json
{
  "code": "-101",
  "messages": "令牌非法",
  "results": null
}
```

---

## 统一响应结构

```json
{
  "code": "100",
  "messages": "",
  "results": {}
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| `code` | string | 状态码（字符串形式） |
| `messages` | string | 提示信息 |
| `results` | object/null | 响应数据 |

---

## 状态码

| 状态码 | 说明 |
|--------|------|
| `100`  | 请求成功 |
| `-100` | 请求失败 |
| `-101` | 令牌非法 |
| `-102` | 获取数据失败 |
| `-404` | 请求错误 |

---

## 淘宝服务（Taobao）

### GetItemDetail — 获取商品详情

**请求地址：** `POST /Taobao/GetItemDetail?Token={自己令牌}`

**请求参数：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `id` | string | 是 | 淘宝宝贝 ID（纯数字） |

**请求示例：**
```
POST /Taobao/GetItemDetail?Token={自己令牌}
Content-Type: application/json

{ "id": "123456789" }
```

**响应数据（results）：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 商品 ID |
| `content` | string | 商品详情原始 JSON 字符串 |

**响应示例：**
```json
{
  "code": "100",
  "messages": "请求成功",
  "results": {
    "id": "123456789",
    "content": "{...}"
  }
}
```

**说明：**
- 采用主任务 + 2s 超时后启动备用任务的双轨并发模式
- 最多重试 3 次，每次使用不同 Android 设备
- 抓取完成后自动记录调用统计到 Redis

---

## 拼多多服务（PinDuoDuo）

### GetItemDetail — 获取商品详情

**请求地址：** `POST /PinDuoDuo/GetItemDetail?Token={自己令牌}`

**请求参数：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `id` | string | 是 | 拼多多商品 ID（纯数字） |

**请求示例：**
```
POST /PinDuoDuo/GetItemDetail?Token={自己令牌}
Content-Type: application/json

{ "id": "987654321" }
```

**响应数据（results）：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 商品 ID |
| `content` | string | 商品详情原始 JSON 字符串 |

**响应示例：**
```json
{
  "code": "100",
  "messages": "请求成功",
  "results": {
    "id": "987654321",
    "content": "{...}"
  }
}
```

**说明：**
- 最多重试 3 次，每次从 Redis 设备池随机取一台 Android 设备
- 抓取失败的设备会从池中移除
- 抓取完成后自动记录调用统计到 Redis

---

### AddDevice — 添加或更新设备

**请求地址：** `POST /PinDuoDuo/AddDevice?Token={自己令牌}`

**请求参数：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `account` | string | 是 | 设备账号（唯一） |
| `info` | string | 否 | 设备信息（JSON 字符串），默认 `{}` |

**请求示例：**
```
POST /PinDuoDuo/AddDevice?Token={自己令牌}
Content-Type: application/json

{
  "account": "user_001",
  "info": "{\"device\":\"Pixel 6\"}"
}
```

**响应示例（成功）：**
```json
{
  "code": "100",
  "messages": "请求成功",
  "results": null
}
```

**说明：**
- 账号已存在时，更新 `info` 并将状态恢复为正常（status=1）
- 账号不存在时，新增设备记录
- 添加/更新成功后自动同步到 Redis 设备缓存

---

### GetDevice — 获取设备信息

**请求地址：** `POST /PinDuoDuo/GetDevice?Token={自己令牌}`

**请求参数：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `account` | string | 否 | 账号，为空则随机返回一个设备 |

**请求示例（指定账号）：**
```
POST /PinDuoDuo/GetDevice?Token={自己令牌}
Content-Type: application/json

{ "account": "user_001" }
```

**请求示例（随机获取）：**
```
POST /PinDuoDuo/GetDevice?Token={自己令牌}
Content-Type: application/json

{}
```

**响应数据（results）：**

| 字段 | 类型 | 说明 |
|------|------|------|
| `account` | string | 账号 |
| `info` | string | 设备信息（JSON 字符串） |
| `device` | string | 手机设备信息（JSON 字符串） |

**响应示例：**
```json
{
  "code": "100",
  "messages": "请求成功",
  "results": {
    "account": "user_001",
    "info": "{\"device\":\"Pixel 6\"}",
    "device": "{\"brand\":\"Samsung\",\"model\":\"Galaxy S21\"}"
  }
}
```

**说明：**
- 指定 `account` 时返回该账号的设备信息
- 不指定 `account` 时随机返回一个可用设备
- 如果设备没有 `device_phone`，系统会自动从 `device_phone.txt` 随机获取，先更新数据库再更新 Redis 缓存

---

### GetDeviceList — 查询设备列表

**请求地址：** `POST /PinDuoDuo/GetDeviceList?Token={自己令牌}`

**请求参数：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `account` | string | 否 | 账号关键词（模糊匹配），为空则不过滤 |
| `status` | int | 否 | 状态过滤：`1`=正常，`-1`=异常，`<0` 不过滤 |
| `page` | int | 否 | 页码，从 1 开始，默认 1 |
| `size` | int | 否 | 每页数量，默认 20 |

**请求示例：**
```
POST /PinDuoDuo/GetDeviceList?Token={自己令牌}
Content-Type: application/json

{
  "account": "user",
  "status": 1,
  "page": 1,
  "size": 20
}
```

**响应数据（results）：**

分页结构：

| 字段 | 类型 | 说明 |
|------|------|------|
| `count` | int | 总记录数 |
| `list` | array | 设备列表 |

列表项字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | int | 设备 ID |
| `account` | string | 账号 |
| `status` | int | 状态（1=正常，-1=异常） |
| `create_time` | string | 创建时间 |

**响应示例：**
```json
{
  "code": "100",
  "messages": "请求成功",
  "results": {
    "count": 100,
    "list": [
      {
        "id": 1,
        "account": "user_001",
        "status": 1,
        "create_time": "2026-01-01T00:00:00"
      }
    ]
  }
}
```

---

### DeleteDevices — 批量删除设备

**请求地址：** `POST /PinDuoDuo/DeleteDevices?Token={自己令牌}`

**请求参数：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `ids` | int[] | 是 | 设备 ID 集合，不能为空 |

**请求示例：**
```
POST /PinDuoDuo/DeleteDevices?Token={自己令牌}
Content-Type: application/json

{ "ids": [1, 2, 3] }
```

**响应示例（成功）：**
```json
{
  "code": "100",
  "messages": "请求成功",
  "results": null
}
```

**说明：**
- 删除成功后自动同步清除对应 Redis 设备缓存

---

### GetRepDataList — 查询抓取记录

**请求地址：** `POST /PinDuoDuo/GetRepDataList?Token={自己令牌}`

**请求参数：**

| 字段 | 类型 | 必填 | 说明 |
|------|------|------|------|
| `page` | int | 否 | 页码，从 1 开始，默认 1 |
| `size` | int | 否 | 每页数量，默认 20 |
| `state` | int | 否 | 状态过滤：`1`=成功，`-1`=失败，`0`=不过滤 |
| `from_time` | string | 否 | 开始时间（`yyyy-MM-dd HH:mm:ss`） |
| `to_time` | string | 否 | 结束时间（`yyyy-MM-dd HH:mm:ss`） |

**请求示例：**
```
POST /PinDuoDuo/GetRepDataList?Token={自己令牌}
Content-Type: application/json

{
  "page": 1,
  "size": 20,
  "state": 1,
  "from_time": "2026-01-01 00:00:00",
  "to_time": "2026-12-31 23:59:59"
}
```

**响应数据（results）：**

分页结构：

| 字段 | 类型 | 说明 |
|------|------|------|
| `count` | int | 总记录数 |
| `list` | array | 记录列表 |

列表项字段：

| 字段 | 类型 | 说明 |
|------|------|------|
| `task_gid` | string | 任务唯一标识 |
| `type` | int | 平台类型（拼多多=2） |
| `item_id` | string | 商品 ID |
| `length` | int | 返回数据长度（字节） |
| `state` | int | 抓取状态（1=成功，-1=失败） |
| `time` | int | 耗时（毫秒） |
| `create_time` | string | 记录时间 |

**响应示例：**
```json
{
  "code": "100",
  "messages": "请求成功",
  "results": {
    "count": 500,
    "list": [
      {
        "task_gid": "abc123",
        "type": 2,
        "item_id": "987654321",
        "length": 2048,
        "state": 1,
        "time": 1500,
        "create_time": "2026-03-21T10:00:00"
      }
    ]
  }
}
```

**说明：**
- 数据来源为 Elasticsearch，按 token_id 自动隔离，只返回当前 Token 的记录