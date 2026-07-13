# Client 接口文档

## 公共说明

- 所有接口通过统一网关调用
- 支持 GET 和 POST（`application/x-www-form-urlencoded` 表单提交）
- 业务数据以 JSON 字符串放在 `d` 参数中

### GET 请求格式

```
/client?c={方法名}&d={JSON字符串}&a={apiKey}&s={签名}&ts={时间戳}
```

### POST 请求格式（Form 表单）

```
POST /client
Content-Type: application/x-www-form-urlencoded

c=WriteFakeDeviceRecord&d={"x_utdid":"abc123","type":1,"event_name":"1000"}&a={apiKey}&s={签名}&ts={时间戳}
```

### 公共参数

| 参数 | 别名 | 类型 | 必填 | 说明 |
|------|------|------|------|------|
| c | cmd | string | 是 | 方法名 |
| d | data | string | 是 | 业务数据（JSON 字符串） |
| a | apiKey | string | 是 | API 密钥 |
| s | sign | string | 是 | 签名：`MD5(timestamp + data + api_secret).ToLower()` |
| ts | timestamp | string | 是 | 时间戳 |
| t | - | string | 否 | 令牌 |
| g | - | string | 否 | 分组 |

### 返回格式

```json
{ "State": 1, "Data": {...}, "Message": "" }
```

---

## 1. WriteFakeDeviceRecord

新增或更新虚拟设备记录。按主键 `(x_utdid, type, event_name)` 判断，存在则更新，不存在则新增。

### 请求参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| x_utdid | string | 是 | 设备 utdid |
| type | int | 是 | 平台类型（1-淘宝 2-京东 3-淘宝匿名 4-京东匿名 5-拼多多） |
| event_name | string | 是 | 事件名称 |
| version | string | 否 | 版本号。新增时为空则默认空字符串；更新时为空或 null 则不更新 version 字段 |
| data_json | string | 否 | 数据 JSON，为空则默认空字符串 |

### 请求示例

GET：
```
/client?c=WriteFakeDeviceRecord&d={"x_utdid":"abc123","type":1,"event_name":"1000","version":"3.0","data_json":"{\"key\":\"value\"}"}&a={apiKey}&s={签名}&ts={时间戳}
```

POST（Form 表单）：
```
POST /client
Content-Type: application/x-www-form-urlencoded

c=WriteFakeDeviceRecord
d={"x_utdid":"abc123","type":1,"event_name":"1000","version":"3.0","data_json":"{\"key\":\"value\"}"}
a={apiKey}
s={签名}
ts={时间戳}
```

### 业务逻辑

1. 按 `(x_utdid, type, event_name)` 查询记录是否存在
2. **存在** → 更新 `data_json`、`update_time`；若 `version` 非空则同时更新 `version`
3. **不存在** → 插入新记录，自动设置 `create_time` 和 `update_time` 为当前时间

### 返回示例

成功：
```json
{
  "State": 1,
  "Data": null,
  "Message": ""
}
```

失败：
```json
{
  "State": -1,
  "Data": null,
  "Message": "操作失败"
}
```

---

## 2. GetFakeDeviceRecord

按 `x_utdid` 和 `type` 查询虚拟设备记录，返回所有匹配数据。

### 请求参数

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| x_utdid | string | 否 | 设备 utdid，为空则不作为筛选条件 |
| type | int | 否 | 平台类型，为 0 则不作为筛选条件 |

### 请求示例

GET：
```
/client?c=GetFakeDeviceRecord&d={"x_utdid":"abc123","type":1}&a={apiKey}&s={签名}&ts={时间戳}
```

POST（Form 表单）：
```
POST /client
Content-Type: application/x-www-form-urlencoded

c=GetFakeDeviceRecord
d={"x_utdid":"abc123","type":1}
a={apiKey}
s={签名}
ts={时间戳}
```

### 返回字段

| 字段 | 类型 | 说明 |
|------|------|------|
| x_utdid | string | 设备 utdid |
| type | int | 平台类型 |
| event_name | string | 事件名称 |
| version | string | 版本号 |
| data_json | string | 数据 JSON |

### 返回示例

```json
{
  "State": 1,
  "Data": [
    {
      "x_utdid": "abc123",
      "type": 1,
      "event_name": "1000",
      "version": "3.0",
      "data_json": "{\"key\":\"value\"}"
    },
    {
      "x_utdid": "abc123",
      "type": 1,
      "event_name": "1011",
      "version": "3.0",
      "data_json": "{\"key2\":\"value2\"}"
    }
  ],
  "Message": ""
}
```

### 备注

- 结果按 `create_time` 降序排列
- 不限制返回条数
- 两个参数都不传时会返回全表数据，请谨慎使用

---

## 3. GetRandomDeviceRecord

从 `device_record` 表中随机获取一个同时包含 event_name 为 `1000` 和 `1011` 的 `x_utdid`，然后返回该 `x_utdid` 的所有事件数据。

### 请求参数

无需传参。

### 请求示例

GET：
```
/client?c=GetRandomDeviceRecord&a={apiKey}&s={签名}&ts={时间戳}
```

POST（Form 表单）：
```
POST /client
Content-Type: application/x-www-form-urlencoded

c=GetRandomDeviceRecord
a={apiKey}
s={签名}
ts={时间戳}
```

### 业务逻辑

1. 筛选 `event_name` 为 `1000` 或 `1011` 的记录
2. 按 `x_utdid` 分组，只保留同时包含这两个事件的 `x_utdid`
3. 使用 PostgreSQL `random()` 函数随机取一个
4. 查询该 `x_utdid` 的所有事件记录

### 返回字段

| 字段　　　　　　　| 类型　 | 说明　　　　　　　　　　　|
| -------------------| --------| ---------------------------|
| x_utdid　　　　　 | string | 随机获取的设备 utdid　　　|
| list　　　　　　　| array　| 该 utdid 下的所有事件数据 |
| list[].x_utdid　　| string | 设备 utdid　　　　　　　　|
| list[].event_name | string | 事件名称　　　　　　　　　|
| list[].data　　　 | string | 数据 JSON　　　　　　　　 |

### 返回示例

```json
{
  "State": 1,
  "Data": [
    {
      "x_utdid": "xyz789",
      "event_name": "1000",
      "data": "{\"header\":\"...\"}"
    },
    {
      "x_utdid": "xyz789",
      "event_name": "1011",
      "data": "{\"body\":\"...\"}"
    },
    {
      "x_utdid": "xyz789",
      "event_name": "2000",
      "data": "{\"extra\":\"...\"}"
    }
  ],
  "Message": ""
}
```

### 备注

- 结果按 `create_time` 降序排列
- 如果没有同时包含 `1000` 和 `1011` 事件的设备，返回空列表
- 每次调用随机返回不同的设备