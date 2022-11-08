package aesstream

import (
	"io"
	"net"
)

type Conn struct {
	net.Conn
	*Cipher
	chunkId uint32
}

func NewConn(c net.Conn, cipher *Cipher) *Conn {
	return &Conn{
		Conn:   c,
		Cipher: cipher,
	}
}

func (c *Conn) Close() error {
	return c.Conn.Close()
}

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.dec == nil {
		iv := make([]byte, c.info.IvLen)
		if _, err = io.ReadFull(c.Conn, iv); err != nil {
			return
		}

		if err = c.initDecrypt(iv); err != nil {
			return
		}

		if len(c.iv) == 0 {
			c.iv = iv
		}
	}

	cipherData := make([]byte, 2048)
	if len(b) > len(cipherData) {
		cipherData = make([]byte, len(b))
	} else {
		cipherData = cipherData[:len(b)]
	}

	n, err = c.Conn.Read(cipherData)
	if n > 0 {
		c.decrypt(b[0:n], cipherData[0:n])
	}

	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	var iv []byte
	if c.enc == nil {
		iv, err = c.initEncrypt()
		if err != nil {
			return
		}
	}

	cipherData := make([]byte, 2048)
	dataSize := len(b) + len(iv)
	if dataSize > len(cipherData) {
		cipherData = make([]byte, dataSize)
	} else {
		cipherData = cipherData[:dataSize]
	}

	if iv != nil {
		// Put initialization vector in buffer, do a single write to send both
		// iv and data.
		copy(cipherData, iv)
	}

	c.encrypt(cipherData[len(iv):], b)
	n, err = c.Conn.Write(cipherData)
	return
}
