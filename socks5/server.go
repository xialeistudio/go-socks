package socks5

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

// 代理服务器
type Server struct {
	version        uint8                   // Socks协议版本
	authenticators map[uint8]Authenticator // 认证器
	listener       net.Listener            // 监听器
	address        string
	port           uint16
	verbose        bool
}

// 实例化服务器
func NewServer(authenticators []Authenticator, verbose bool) *Server {
	// 构造认证方法map
	authMap := make(map[uint8]Authenticator)
	for _, authenticator := range authenticators {
		authMap[authenticator.Method()] = authenticator
	}

	return &Server{
		version:        SocksVersion,
		authenticators: authMap,
		verbose:        verbose,
	}
}

// 监听
func (p *Server) ListenAndServe(address string, port uint16) error {
	p.address = address
	p.port = port
	var err error

	p.listener, err = net.Listen("tcp", net.JoinHostPort(address, strconv.Itoa(int(port))))
	if err != nil {
		return err
	}
	log.Printf("listen on %s:%d.", address, port)
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return err
		}

		go p.handleConnect(conn)
	}
}

// 接收客户端服务
func (p Server) handleConnect(conn net.Conn) error {
	if p.verbose {
		log.Printf("%s connected.", conn.RemoteAddr().String())
	}

	defer conn.Close()
	var (
		br      = bufio.NewReader(conn)
		bw      = bufio.NewWriter(conn)
		version uint8
	)
	if err := binary.Read(br, binary.BigEndian, &version); err != nil {
		return err
	}
	// 协议版本处理
	if version != p.version {
		return fmt.Errorf("unsupported socks version: %d", version)
	}

	if p.verbose {
		log.Printf("%s authenticating.", conn.RemoteAddr().String())
	}
	// 认证协商
	if err := p.authenticate(br, bw); err != nil {
		return err
	}

	if p.verbose {
		log.Printf("%s send commands.", conn.RemoteAddr().String())
	}

	// 处理命令
	request, err := newRequest(br)
	if err != nil {
		return err
	}
	if request.cmd != CmdConnect {
		response := newResponse(StatusCommandNotSupported, p.address, p.port)
		return response.send(bw)
	}
	// 连接目标主机
	if p.verbose {
		log.Printf("%s connecting upstream %s:%d.", conn.RemoteAddr().String(), request.address, request.port)
	}

	upstream, err := net.Dial("tcp", net.JoinHostPort(request.address, strconv.Itoa(int(request.port))))
	if err != nil {
		response := newResponse(StatusHostUnreachable, p.address, p.port)
		return response.send(bw)
	}
	// 发送成功响应
	response := newResponse(StatusOk, p.address, p.port)
	err = response.send(bw)
	if err != nil {
		return err
	}
	if p.verbose {
		log.Printf("%s start proxying.", conn.RemoteAddr().String())
	}
	// 请求处理
	ch := make(chan error, 2)
	// upstream -> client
	go p.proxy(bw, upstream, ch)
	// client -> upstream
	go p.proxy(upstream, br, ch)

	for i := 0; i < 2; i++ {
		err := <-ch
		if err != nil {
			return err
		}
	}
	return nil
}

// 认证协商处理
func (p *Server) authenticate(reader io.Reader, writer *bufio.Writer) error {
	// 读取支持的方法列表
	var (
		count   uint8
		methods []byte
	)
	if err := binary.Read(reader, binary.BigEndian, &count); err != nil {
		return err
	}
	methods = make([]uint8, count)
	if _, err := io.ReadAtLeast(reader, methods, int(count)); err != nil {
		return err
	}

	for _, method := range methods {
		authenticator, ok := p.authenticators[method]
		if ok {
			return authenticator.Authenticate(reader, writer)
		}
	}
	_, _ = writer.Write([]byte{p.version, AuthMethodNotAcceptable})
	_ = writer.Flush()
	return errors.New("unsupported authenticate method")
}

// 代理数据
func (Server) proxy(dst io.Writer, src io.Reader, ch chan error) {
	_, err := io.Copy(dst, src)
	if err != nil {
		ch <- err
	}
}
