# golang socks5服务器
基于net包开发，使用协程维持客户端连接

代码量比较少，socks5协议也比较简单，可以作为TCP协议开发入门例子

## 安装

```bash
go get github.com/xialeistudio/go-socks
```

## 使用

```go
package main

import (
	"github.com/xialeistudio/go-socks/socks5"
	"github.com/xialeistudio/go-socks/socks5/authenticator"
	"log"
)

func main() {
	accounts := map[string]string{
		"username": "password",
	}
	authenticators := []socks5.Authenticator{
		authenticator.NewNoneAuthenticator(), // 免密码认证
		authenticator.NewUserPasswordAuthenticator(accounts), // 账号和密码认证
	}
	server := socks5.NewServer(authenticators, true)
	log.Println(server.ListenAndServe("127.0.0.1", 10000))
}
```

## 功能

1. 免认证/账号密码认证
2. 仅支持CONNECT命令

## TODO

1. [ ] 支持ruleset
2. [ ] 支持BIND和UDP ASSOCIATE命令

## 作者博客

[每天进步一点点](https://www.ddhigh.com)