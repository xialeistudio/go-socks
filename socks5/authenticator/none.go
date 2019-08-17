package authenticator

import (
	"bufio"
	"github.com/xialeistudio/go-socks/socks5"
	"io"
)

// 免认证的认证器
type NoneAuthenticator struct{}

// 实例化
func NewNoneAuthenticator() *NoneAuthenticator {
	return &NoneAuthenticator{}
}

// 进行认证
func (NoneAuthenticator) Authenticate(reader io.Reader, writer *bufio.Writer) (err error) {
	_, err = writer.Write([]byte{socks5.SocksVersion, socks5.AuthMethodNone})
	if err != nil {
		return
	}
	return writer.Flush()
}

// 获取方法Code
func (NoneAuthenticator) Method() uint8 {
	return socks5.AuthMethodNone
}
