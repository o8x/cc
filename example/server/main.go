package main

import (
	"io"
	"log"
	"net"

	"github.com/o8x/cc"
)

var key = string([]byte{
	0x9d, 0x4f, 0xad, 0x7d, 0xf2, 0x1f, 0x20, 0xe,
	0xac, 0x70, 0x71, 0x11, 0x13, 0xe4, 0x0, 0x32,
	0x5a, 0xb0, 0x32, 0x44, 0x72, 0x36, 0x20, 0x92,
})

var username = "ERW0"
var password = "HE9W336ZCIW"

func main() {
	l, err := net.Listen("tcp", "localhost:51904")
	if err != nil {
		panic(err)
	}

	log.Printf("server listen on tcp://%s", l.Addr().String())

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf(err.Error())
			continue
		}

		log.Printf("new client connect: %s", conn.RemoteAddr())

		go func(conn net.Conn) {
			c, err := cc.NewConn(conn, key)
			if err != nil {
				return
			}

			if _, err := c.Handshake(cc.TypeServer); err != nil {
				if err != io.EOF {
					log.Printf("handshake err: %s", err.Error())
					return
				}
			}

			if _, err := c.AuthHandshake(&cc.Auth{Username: username, Password: password}); err != nil {
				if err != io.EOF {
					log.Printf("auth handshake err: %s", err.Error())
					return
				}
			}

			req, err := c.ATYPHandshake()
			if err != nil {
				log.Printf("requests handshake err: %s", err.Error())
				return
			}

			out, err := net.Dial("tcp", req.Target)
			if err != nil {
				log.Printf("dial target err: %s", err.Error())
				return
			}

			IoBind(c, out, func(err error) {
				_ = out.Close()
				_ = c.Close()
			})
		}(conn)
	}
}
