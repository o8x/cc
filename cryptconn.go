package cc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/o8x/cc/internal"
	"github.com/o8x/cc/internal/aesstream"
	"github.com/o8x/cc/internal/cipher"
)

const (
	CmdAuth            = 0x01
	CmdConnect         = 0x02
	AuthMethodNone     = 0x00
	AuthMethodPassword = 0x01
	AtypDomain         = 0x01
	AtypIP             = 0x02
	CmdSuccess         = 0x01
	CmdFailed          = 0x02
	CmdNotFound        = 0x03
)

const (
	TypeClient = 0x02
	TypeServer = 0x05
)

var (
	CmdNotFoundReply    = []byte{0x01, CmdNotFound}
	AuthFailedReply     = []byte{CmdAuth, 0x01, CmdFailed}
	AuthSuccessReply    = []byte{CmdAuth, 0x01, CmdSuccess}
	ConnectSuccessReply = []byte{CmdConnect, 0x01, CmdSuccess}
	HandshakeReply      = []byte{0x00, 0xcc, 0x10, cipher.Aes192CFB, TypeServer}
	HandshakeRequest    = []byte{0x00, 0xcc, 0x10, cipher.Aes192CFB, TypeClient}
)

type CC struct {
	Protocol string       `json:"protocol"`
	Version  string       `json:"version"`
	Cipher   *cipher.Info `json:"cipher"`
	Typ      string       `json:"typ"`
}

type Connect struct {
	ATYP   string `json:"atyp"`
	Target string `json:"target"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
}

func (r Connect) String() string {
	return fmt.Sprintf("ATYP: %s, Target: %s", r.ATYP, r.Target)
}

type Auth struct {
	Type     string `json:"type"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a Auth) String() string {
	return fmt.Sprintf("username: %s, password: %s", a.Username, a.Password)
}

type CryptConn struct {
	net.Conn
	key          []byte
	r            io.Reader
	w            io.Writer
	Debug        bool
	CipherStream *aesstream.Conn
}

func NewConn(conn net.Conn, sKey string) (*CryptConn, error) {
	c := &CryptConn{
		Conn:  conn,
		Debug: false,
		key:   make([]byte, 24),
	}

	bKey, _ := hex.DecodeString(sKey)
	copy(c.key, bKey[0:24])
	return c, nil
}

func (c *CryptConn) AuthHandshake(auth1 *Auth) (*Auth, error) {
	buf := bytes.NewBuffer(nil)
	if err := internal.ReadConnBuffer(c, buf); err != nil {
		return nil, err
	}

	var auth *Auth
	bs := buf.Bytes()

	if bs[0] != CmdAuth {
		_ = c.Replay(append([]byte{CmdAuth}, CmdNotFoundReply...))
		return nil, fmt.Errorf("auth cmd wrong")
	}

	switch bs[1] {
	case AuthMethodNone:
		return nil, fmt.Errorf("auth required")
	case AuthMethodPassword:
		if buf.Len() < 2 {
			return nil, fmt.Errorf("auth failed")
		}

		// CMD(1) + 认证方法(1) + 用户名长度(1) + 用户名(...) + 密码长度(1)
		usernameLenIndex := 1 + 1 + 1 - 1 // 从 0 开始所以需要减一
		usernameLen := int(bs[usernameLenIndex])
		usernameEnd := usernameLenIndex + usernameLen
		usernameStart := usernameLenIndex + 1
		if buf.Len() < usernameEnd {
			return nil, fmt.Errorf("username failed")
		}

		passwordLen := int(bs[usernameEnd+1])
		if buf.Len() < (usernameEnd + passwordLen) {
			return nil, fmt.Errorf("password failed")
		}

		auth = &Auth{
			// : 取值，后面的数字的索引并不会被取到，假设 [4:8] 实际上只会取到 4:7 这一段，所以需要加一
			Username: string(bs[usernameStart : usernameEnd+1]),
			// 用户名取值 +1，密码长度索引位 + 1
			Password: string(bs[usernameEnd+1+1:]),
		}

		if len(auth.Username) != usernameLen {
			return nil, fmt.Errorf("username length failed")
		}

		if len(auth.Password) != passwordLen {
			return nil, fmt.Errorf("password length failed")
		}
	default:
		return nil, fmt.Errorf("auth method not supported")
	}

	if auth1 != nil {
		if auth.Username != auth1.Username || auth.Password != auth1.Password {
			_ = c.Replay(AuthFailedReply)
			return auth, fmt.Errorf("auth failed")
		}

		return auth, c.Replay(AuthSuccessReply)
	}

	return auth, nil
}

func (c *CryptConn) Replay(data []byte) error {
	_, err := c.Write(data)
	return err
}

func (c *CryptConn) ATYPHandshake() (*Connect, error) {
	buf := bytes.NewBuffer(nil)
	if err := internal.ReadConnBuffer(c, buf); err != nil {
		return nil, err
	}

	bs := buf.Bytes()
	if bs[0] != CmdConnect {
		_ = c.Replay(append([]byte{CmdAuth}, CmdNotFoundReply...))
		return nil, fmt.Errorf("connect cmd wrong")
	}

	if buf.Len() < 3 {
		return nil, fmt.Errorf("requests handshake failed")
	}

	atyps := map[int]string{
		AtypDomain: "domain",
		AtypIP:     "ip",
	}

	t, ok := atyps[int(bs[1])]
	if !ok {
		return nil, fmt.Errorf("atyp not supported")
	}

	target := string(bs[2:])
	res := &Connect{
		ATYP:   t,
		Target: target,
	}

	if strings.Contains(target, ":") {
		host, port, _ := net.SplitHostPort(target)
		res.Host = host

		intPort, err := strconv.ParseInt(port, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("port must be int")
		}
		res.Port = int(intPort)
	}

	return res, c.Replay(ConnectSuccessReply)
}

// Handshake @see RFC.md
func (c *CryptConn) Handshake(typ int) (*CC, error) {
	var err error
	if typ == TypeClient {
		_, err = c.Conn.Write(HandshakeRequest)
	} else if typ == TypeServer {
		_, err = c.Conn.Write(HandshakeReply)
	} else {
		return nil, fmt.Errorf("type not in server, client")
	}

	buf := bytes.NewBuffer(nil)
	if err := internal.ReadConnBuffer(c.Conn, buf); err != nil {
		return nil, err
	}

	if buf.Len() != 5 {
		return nil, fmt.Errorf("not cc protocol")
	}

	bs := buf.Bytes()
	protocol := bs[1]
	version := bs[2]
	requestCipher := int(bs[3])
	rType := int(bs[4])

	if protocol != 0xcc {
		return nil, fmt.Errorf("protocol not supported")
	}

	if version < 0x10 {
		return nil, fmt.Errorf("version not supported")
	}

	if !cipher.Check(requestCipher) {
		return nil, fmt.Errorf("newCipher method not supported")
	}

	typeMap := map[int]string{
		TypeServer: "client",
		TypeClient: "server",
	}

	typeName, ok := typeMap[rType]
	if !ok {
		return nil, fmt.Errorf("type not supported")
	}

	info := cipher.GetInfo(requestCipher)

	// 包装加密器
	newCipher, err := aesstream.NewCipher(c.key, info)
	if err != nil {
		return nil, err
	}
	c.CipherStream = aesstream.NewConn(c.Conn, newCipher)

	return &CC{
		Protocol: "cc",
		Version:  string(version),
		Cipher:   info,
		Typ:      typeName,
	}, nil
}

func (c *CryptConn) Read(b []byte) (int, error) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("cryptconn read crashed %s", err)
		}
	}()

	return c.CipherStream.Read(b)
}

func (c *CryptConn) Write(b []byte) (n int, err error) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("cryptconn write crashed %s", err)
		}
	}()

	return c.CipherStream.Write(b)
}
