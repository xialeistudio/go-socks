package socks5

import (
	"fmt"
	"io"
	"net"
)

const (
	CmdConnect   uint8 = 0x01
	CmdBind            = 0x02
	CmdAssociate       = 0x03
)

const (
	AddressIpv4   uint8 = 0x01
	AddressDomain       = 0x03
	AddressIpv6         = 0x04
)

// 客户端请求
type request struct {
	version     uint8
	cmd         uint8
	rsv         uint8
	addressType uint8
	address     string
	port        uint16
}

func newRequest(reader io.Reader) (*request, error) {
	data := make([]byte, 128)
	count, err := reader.Read(data)
	if err != nil {
		return nil, err
	}
	req := &request{
		version:     data[0],
		cmd:         data[1],
		rsv:         data[2],
		addressType: data[3],
	}
	switch req.addressType {
	case AddressIpv4:
		req.address = net.IPv4(data[4], data[5], data[6], data[7]).String()
	case AddressDomain:
		req.address = string(data[5 : count-4-2]) // 2字节端口+1字节版本+1字节cmd+1字节rsv+1字节地址类型+1字节域名长度
	case AddressIpv6:
		req.address = net.IP{data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19]}.String()
	default:
		return nil, fmt.Errorf("unsupported address type: %d", req.addressType)
	}
	req.port = uint16(int(data[count-2])<<8 | int(data[count-1]))
	return req, nil
}
