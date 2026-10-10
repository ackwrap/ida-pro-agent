package mcpserver

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

const cursorKeyBytes = 32

type cursorCodec struct {
	key [cursorKeyBytes]byte
}

func newCursorCodec() (*cursorCodec, error) {
	codec := &cursorCodec{}
	if _, err := rand.Read(codec.key[:]); err != nil {
		return nil, fmt.Errorf("generate cursor signing key: %w", err)
	}
	return codec, nil
}

func (codec *cursorCodec) encode(kind, binding, internal string) (string, error) {
	if codec == nil || internal == "" || strings.ContainsAny(kind, ".\x00") || binding == "" {
		return "", errors.New("cursor encoding input is invalid")
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(internal))
	unsigned := kind + "." + payload
	tag := codec.sign(unsigned, binding)
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(tag), nil
}

func (codec *cursorCodec) decode(kind, binding, cursor string) (string, error) {
	if codec == nil || binding == "" {
		return "", errors.New("cursor decoder is unavailable")
	}
	parts := strings.Split(cursor, ".")
	if len(parts) != 3 || parts[0] != kind {
		return "", errors.New("cursor format is invalid")
	}
	providedTag, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(providedTag) != sha256.Size {
		return "", errors.New("cursor signature is invalid")
	}
	unsigned := parts[0] + "." + parts[1]
	if !hmac.Equal(providedTag, codec.sign(unsigned, binding)) {
		return "", errors.New("cursor signature is invalid")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil || len(payload) == 0 {
		return "", errors.New("cursor payload is invalid")
	}
	return string(payload), nil
}

func (codec *cursorCodec) sign(unsigned, binding string) []byte {
	mac := hmac.New(sha256.New, codec.key[:])
	_, _ = mac.Write([]byte(unsigned))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(binding))
	return mac.Sum(nil)
}
