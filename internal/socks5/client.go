package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// Client represents a SOCKS5 client.
type Client struct {
	ProxyAddr string
	Username  string
	Password  string
}

// Dial connects to the target address via the SOCKS5 proxy.
func (c *Client) Dial(target string) (net.Conn, error) {
	conn, err := net.Dial("tcp", c.ProxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to proxy: %w", err)
	}

	if err := c.handshake(conn); err != nil {
		conn.Close()
		return nil, err
	}

	if err := c.sendRequest(conn, target); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

func (c *Client) handshake(conn net.Conn) error {
	// Methods: No Auth (0) and User/Pass (2) if credentials provided
	methods := []byte{MethodNoAuth}
	if c.Username != "" {
		methods = append(methods, MethodUserPass)
	}

	// Send Greeting
	req := append([]byte{Version5, uint8(len(methods))}, methods...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	// Read Server Choice
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}

	if resp[0] != Version5 {
		return ErrVersionNotSupported
	}

	method := resp[1]
	if method == MethodUserPass {
		return c.authenticate(conn)
	} else if method == MethodNoAuth {
		return nil
	}

	return ErrAuthFailed
}

func (c *Client) authenticate(conn net.Conn) error {
	req := []byte{0x01, uint8(len(c.Username))}
	req = append(req, []byte(c.Username)...)
	req = append(req, uint8(len(c.Password)))
	req = append(req, []byte(c.Password)...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}

	if resp[1] != 0x00 {
		return ErrAuthFailed
	}
	return nil
}

func (c *Client) sendRequest(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(portStr)

	// Version, Cmd, Reserved, AddrType
	req := []byte{Version5, CmdConnect, 0x00}

	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			req = append(req, AddrIPv4)
			req = append(req, ipv4...)
		} else {
			req = append(req, AddrIPv6)
			req = append(req, ip...)
		}
	} else {
		req = append(req, AddrDomain, uint8(len(host)))
		req = append(req, []byte(host)...)
	}

	p := make([]byte, 2)
	binary.BigEndian.PutUint16(p, uint16(port))
	req = append(req, p...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	// Read Response
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}

	if resp[1] != 0x00 {
		return ErrGeneralFailure
	}

	// Skip remaining address data
	var skip int
	switch resp[3] {
	case AddrIPv4:
		skip = 4
	case AddrDomain:
		lenBuf := make([]byte, 1)
		io.ReadFull(conn, lenBuf)
		skip = int(lenBuf[0])
	case AddrIPv6:
		skip = 16
	}
	skip += 2 // Port

	io.ReadFull(conn, make([]byte, skip))
	return nil
}
