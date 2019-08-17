package authenticator

import (
	"bufio"
	"encoding/binary"
	"github.com/xialeistudio/go-socks/socks5"
	"io"
)

// 账号密码认证
type UserPasswordAuthenticator struct {
	users map[string]string
}

func NewUserPasswordAuthenticator(users map[string]string) *UserPasswordAuthenticator {
	return &UserPasswordAuthenticator{
		users: users,
	}
}

func (p UserPasswordAuthenticator) Authenticate(reader io.Reader, writer *bufio.Writer) (err error) {
	if _, err = writer.Write([]byte{socks5.SocksVersion, socks5.AuthMethodUserPassword}); err != nil {
		return
	}
	if err = writer.Flush(); err != nil {
		return
	}

	var (
		version        uint8  // 子协商版本
		userLength     uint8  // 用户名长度
		username       []byte // 用户名
		passwordLength uint8  // 密码长度
		password       []byte // 密码
	)

	if err := binary.Read(reader, binary.BigEndian, &version); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &userLength); err != nil {
		return err
	}
	// 读取用户名
	username = make([]byte, userLength)
	if err := binary.Read(reader, binary.BigEndian, &username); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &passwordLength); err != nil {
		return err
	}
	// 读取密码
	password = make([]byte, passwordLength)
	if err := binary.Read(reader, binary.BigEndian, &password); err != nil {
		return err
	}
	// 验证账号密码
	if p.users[string(username)] != string(password) {
		if _, err = writer.Write([]byte{version, 0x01}); err != nil {
			return
		}
		err = writer.Flush()
		return
	}
	if _, err = writer.Write([]byte{version, 0x00}); err != nil {
		return
	}
	err = writer.Flush()
	return
}

func (UserPasswordAuthenticator) Method() uint8 {
	return socks5.AuthMethodUserPassword
}
