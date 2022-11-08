package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/o8x/cc"
)

var key = string([]byte{
	0x9d, 0x4f, 0xad, 0x7d, 0xf2, 0x1f, 0x20, 0xe,
	0xac, 0x70, 0x71, 0x11, 0x13, 0xe4, 0x0, 0x32,
	0x5a, 0xb0, 0x32, 0x44, 0x72, 0x36, 0x20, 0x92,
})

var username = "ERW0"
var password = "HE9W336ZCIW"
var server = "localhost:51904"

func main() {
	dialer := cc.Dialer{
		Key:          key,
		ProxyNetwork: "tcp",
		ProxyAddress: server,
		Auth: &cc.Auth{
			Type:     "",
			Username: username,
			Password: password,
		},
	}

	hc := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}

	get, err := hc.Get("https://baidu.com")
	if err != nil {
		log.Fatal("http error: ", err)
	}

	all, _ := io.ReadAll(get.Body)
	fmt.Println(string(all))
}
