package transport

import "net"

func NewLocalDialer() *NamedPipeDialer { return NewNamedPipeDialer() }

func ValidatePeer(net.Conn, uint32) error { return nil }
