CryptConn
======

![GitHub top language](https://img.shields.io/github/languages/top/o8x/cc)
[![Go Report Card](https://goreportcard.com/badge/github.com/o8x/cc)](https://goreportcard.com/report/github.com/o8x/cc)
[![CodeFactor](https://www.codefactor.io/repository/github/o8x/cc/badge)](https://www.codefactor.io/repository/github/o8x/cc)
[![Go Reference](https://pkg.go.dev/badge/github.com/o8x/cc.svg)](https://pkg.go.dev/github.com/o8x/cc)
[![LICENSE](https://img.shields.io/github/license/o8x/cc.svg)](https://github.com/o8x/cc/blob/main/LICENSE)

net.Conn 的封装，采用 cc1 协议进行加密数据传输

# CC1

CC1 是 CC(CryptConn) 协议族的 1.0 版本，本质上是使用 aes 对传输进行加解密的一种 socks like 协议

# CC1 RFC

## 协议握手：

```text
+-------------------------------------+
| protocol | version | cipher |  type |
|-----------------------------|--------
|   2byte  |  1byte  |  1byte | 1byte |
+-------------------------------------+

protocol：协议
    - cc: 0x00cc
version: 版本号
    - 0x10: 1.0
cipher: 加密方法
    - 0x00: 明文
    - 0x01: aes-128-cfb
    - 0x02: aes-192-cfb
    - 0x03: aes-256-cfb
    - 0x11: aes-128-ctr
    - 0x12: aes-192-ctr
    - 0x13: aes-256-ctr
type: 类型
    - 0x02: 客户端
    - 0x05: 服务端
```

示例

```text
        00cc100102
client ---------------> server
        00cc100105
client <--------------- server
```

## 权限验证

```text
+--------------------------------------------------------------------+
|  cmd  | method | username-len | username | password-len | password |
+--------------------------------------------------------------------+
| 1byte | 1byte  |     1byte    |   -bit   |     1byte    |   -bit   |
+--------------------------------------------------------------------+

cmd: 命令类型
    - 0x01：权限验证
    - 0x02：CONNECT
method: 认证方法
    - 0x00: 无权限认证
    - 0x01: USERNAME/PASSWORD 认证
username-len: 用户名长度
username: 用户名
password-len: 密码长度
password: 密码
```

### 响应

```text
+--------------------------+
|  cmd  |  method |  reply |
+--------------------------+
| 1byte |  1byte  |  1byte |
+--------------------------+

method: 认证方法
    - 0x00: 无权限认证
    - 0x01: USERNAME/PASSWORD 认证
reply: 响应
    - 0x01: CMD成功
    - 0x02: CMD失败
    - 0x03: CMD错误
```

## CONNECT

类似 socks5 的 Requests 部分

```text
+------------------------+
|  cmd  | ATYP  | target |
+------------------------+
| 1byte | 1byte |  -byte  |
+------------------------+

ATYP: target 的类型
    - 0x01: 域名
    - 0x02: IP
target: 目标地址
```

### 响应

```text
+------------------------+
|  cmd  |  ATYP  | reply |
+------------------------+
| 1byte | 1byte | 1byte  |
+------------------------+

ATYP: target 的类型
    - 0x01: 域名
    - 0x02: IP
reply: 响应
    - 0x01: CMD成功
    - 0x02: CMD失败
    - 0x03: CMD错误
    - 0x04: 不允许连接
    - 0x05: 找不到主机
    - 0x06: 不支持的 ATYP
```

# Golang Example

- Server [example/server.go](./example/server/main.go)
- Client [example/client.go](./example/client/main.go)
