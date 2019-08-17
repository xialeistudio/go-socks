package socks5

import (
	"bufio"
	"encoding/binary"
)

const (
	StatusOk                     uint8 = 0x00
	StatusIntervalError                = 0x01
	StatusNotAlloed                    = 0x02
	StatusNetworkUnreachable           = 0x03
	StatusHostUnreachable              = 0x04
	StatusConnectRefused               = 0x05
	StatusTtlExpired                   = 0x06
	StatusCommandNotSupported          = 0x07
	StatusAddressTypeUnSupported       = 0x08
)

// 服务器响应
type response struct {
	version     uint8
	rep         uint8
	rsv         uint8
	addressType uint8
	address     string // 会被忽略
	port        uint16
}

func newResponse(rep uint8, address string, port uint16) *response {
	return &response{
		version:     SocksVersion,
		rep:         rep,
		rsv:         0,
		addressType: AddressIpv4,
		address:     address,
		port:        port,
	}
}

// 发送响应
func (p response) send(writer *bufio.Writer) error {
	if err := binary.Write(writer, binary.BigEndian, &p.version); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, &p.rep); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, &p.rsv); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, &p.addressType); err != nil {
		return err
	}
	address := []byte{0x00, 0x00, 0x00, 0x00}
	if err := binary.Write(writer, binary.BigEndian, &address); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, &p.port); err != nil {
		return err
	}
	return writer.Flush()
}
