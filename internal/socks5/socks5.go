package socks5

import "errors"

const (
	Version5 = 0x05
	Version4 = 0x04

	// Commands
	CmdConnect      = 0x01
	CmdBind         = 0x02
	CmdUdpAssociate = 0x03

	// Address Types
	AddrIPv4   = 0x01
	AddrDomain = 0x03
	AddrIPv6   = 0x04

	// Auth Methods
	MethodNoAuth   = 0x00
	MethodUserPass = 0x02
	MethodNoAccept = 0xFF
)

var (
	ErrVersionNotSupported = errors.New("socks version not supported")
	ErrAuthFailed          = errors.New("authentication failed")
	ErrAddrTypeNotSupport  = errors.New("address type not supported")
	ErrCommandNotSupport   = errors.New("command not supported")
	ErrGeneralFailure      = errors.New("general socks server failure")
)
