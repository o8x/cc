package internal

import (
	"bytes"
	"net"
)

func ReadConnBuffer(conn net.Conn, buf *bytes.Buffer) error {
	b := make([]byte, 32*1024)
	nr, err := conn.Read(b)
	if err != nil {
		return err
	}

	buf.Write(b[0:nr])
	return nil
}
