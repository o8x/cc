package aesstream

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	cipher2 "github.com/o8x/cc/internal/cipher"
)

type Cipher struct {
	enc  cipher.Stream
	dec  cipher.Stream
	key  []byte
	info *cipher2.Info
	ota  bool
	iv   []byte
}

// NewCipher creates a cipher that can be used in Dial() etc.
// Use cipher.Copy() to create a new cipher with the same method and password
// to avoid the cost of repeated cipher initialization.
func NewCipher(key []byte, info *cipher2.Info) (c *Cipher, err error) {
	c = &Cipher{
		key:  key,
		info: info,
	}

	c.ota = false
	return c, nil
}

// Initializes the block cipher with CFB mode, returns IV.
func (c *Cipher) initEncrypt() (iv []byte, err error) {
	if c.iv == nil {
		iv = make([]byte, c.info.IvLen)
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		c.iv = iv
	} else {
		iv = c.iv
	}
	c.enc, err = c.info.NewStream(c.key, iv, cipher2.Encrypt)
	return
}

func (c *Cipher) initDecrypt(iv []byte) (err error) {
	c.dec, err = c.info.NewStream(c.key, iv, cipher2.Decrypt)
	return
}

func (c *Cipher) encrypt(dst, src []byte) {
	c.enc.XORKeyStream(dst, src)
}

func (c *Cipher) decrypt(dst, src []byte) {
	c.dec.XORKeyStream(dst, src)
}
