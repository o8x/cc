package main

import (
	"io"
	"log"
	"strings"
)

func IoBind(dst io.ReadWriteCloser, src io.ReadWriteCloser, fn func(error)) {
	go func() {
		defer func() {
			if err := recover(); err != nil {
				log.Print("bind crashed")
			}
		}()

		e := make(chan error, 2)
		go func() {
			defer func() {
				if err := recover(); err != nil {
					log.Print("dst to src crashed")
				}
			}()

			err := ioCopy(dst, src)
			if err != nil {
				if strings.Contains(err.Error(), "use of closed network connection") || err == io.EOF {
					log.Print("tcp conn close")
					e <- nil
					return
				}

				log.Print("dst to src proxy error")
			}
			e <- err
		}()

		go func() {
			defer func() {
				if err := recover(); err != nil {
					log.Print("src to dst crashed")
				}
			}()

			err := ioCopy(src, dst)
			if err != nil {
				if strings.Contains(err.Error(), "EOF") || err == io.EOF {
					e <- nil
					return
				}

				log.Print("src to dst proxy error ", err)
			}
			e <- err
		}()

		err := <-e
		_ = dst.Close()
		_ = src.Close()
		if fn != nil {
			fn(err)
		}
	}()
}

func ioCopy(dst io.ReadWriter, src io.ReadWriter) (err error) {
	buf := make([]byte, 2048)

	n := 0
	for {
		n, err = src.Read(buf)
		if n > 0 {
			if _, e := dst.Write(buf[0:n]); e != nil {
				return e
			}
		}
		if err != nil {
			return
		}
	}
}
