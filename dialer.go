package cc

import (
	"bytes"
	"context"
	"fmt"
	"net"

	"github.com/o8x/cc/internal"
)

type Dialer struct {
	ProxyNetwork string `json:"proxy_network"`
	ProxyAddress string `json:"proxy_address"`
	Auth         *Auth  `json:"auth"`
	Key          string `json:"key"`
}

func (d *Dialer) DialWithConn(_ context.Context, dial net.Conn, _, address string) (net.Addr, error) {
	user := []byte(d.Auth.Username)
	pw := []byte(d.Auth.Password)
	data := []byte{CmdAuth, 0x01}
	data = append(data, byte(len(user)))
	data = append(data, user...)
	data = append(data, byte(len(pw)))
	data = append(data, pw...)
	if _, err := dial.Write(data); err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(nil)
	if err := internal.ReadConnBuffer(dial, buf); err != nil {
		return nil, err
	}

	authReply := buf.Bytes()
	if authReply[1] != 0x01 || authReply[2] != 0x01 {
		return nil, fmt.Errorf("auth password failed")
	}

	data = []byte{CmdConnect, 0x01}
	_, err := dial.Write(append(data, []byte(address)...))

	buf = bytes.NewBuffer(nil)
	if err := internal.ReadConnBuffer(dial, buf); err != nil {
		return nil, err
	}

	return nil, err
}

func (d *Dialer) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	return d.Dial(network, address)
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	var c net.Conn
	c, err := net.Dial(d.ProxyNetwork, d.ProxyAddress)
	if err != nil {
		return nil, err
	}

	if c, err = NewConn(c, d.Key); err != nil {
		return nil, err
	}

	nextConn := c.(*CryptConn)
	if _, err = nextConn.Handshake(TypeClient); err != nil {
		return nil, err
	}

	if _, err := d.DialWithConn(context.Background(), nextConn, network, address); err != nil {
		c.Close()
		return nil, err
	}

	return nextConn, nil
}
