package socks5

import (
	"bufio"
	"io"
)

// 支持的认证方式
const (
	AuthMethodNone          uint8 = 0x00 // 无需认证
	AuthMethodUserPassword        = 0x02 // 账号密码认证
	AuthMethodNotAcceptable       = 0xff // 无可认证方法
)

// 身份验证器
type Authenticator interface {
	Authenticate(reader io.Reader, writer *bufio.Writer) error
	Method() uint8
}
