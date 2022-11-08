package cipher

import (
	"crypto/aes"
	"crypto/cipher"
)

const (
	Aes128CFB = 0x01
	Aes192CFB = 0x02
	Aes256CFB = 0x03
	Aes128CTR = 0x11
	Aes192CTR = 0x12
	Aes256CTR = 0x13
)

type DecOrEnc int

const (
	Decrypt DecOrEnc = iota
	Encrypt
)

type Info struct {
	Name      string
	KeyLen    int
	IvLen     int
	NewStream func(key, iv []byte, doe DecOrEnc) (cipher.Stream, error)
}

var s = map[int]*Info{
	Aes128CFB: {"aes-128-cfb", 16, 16, newAESCFBStream},
	Aes192CFB: {"aes-192-cfb", 24, 16, newAESCFBStream},
	Aes256CFB: {"aes-256-cfb", 32, 16, newAESCFBStream},
	Aes128CTR: {"aes-128-ctr", 16, 16, newAESCTRStream},
	Aes192CTR: {"aes-192-ctr", 24, 16, newAESCTRStream},
	Aes256CTR: {"aes-256-ctr", 32, 16, newAESCTRStream},
}

func newAESCFBStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if doe == Encrypt {
		return cipher.NewCFBEncrypter(block, iv), nil
	}

	return cipher.NewCFBDecrypter(block, iv), nil
}

func newAESCTRStream(key, iv []byte, doe DecOrEnc) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

func Check(c int) bool {
	_, ok := s[c]
	return ok
}

func GetInfo(c int) *Info {
	return s[c]
}
