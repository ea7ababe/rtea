// This is a Go implementation of RTEA (Ruptor's TEA or Repaired TEA)
// block cipher.
package rtea

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

const BlockSize = 8

var enc = binary.LittleEndian

var KeySizeError = errors.New("invalid RTEA key size")

type rtea struct {
	key []uint32
}

// Creates a new RTEA cipher instance with a given key.
// The key must be dividable by 4.
func NewCipher(key []byte) (cipher.Block, error) {
	l := len(key)
	if l%4 != 0 {
		return nil, KeySizeError(l)
	}
	c := rtea{}
	c.key = make([]uint32, l/4)
	for i := range c.key {
		c.key[i] = enc.Uint32(key)
		key = key[4:]
	}

	return c, nil
}

func (c rtea) BlockSize() int {
	return BlockSize
}

func (c rtea) Encrypt(dst, src []byte) {
	a := enc.Uint32(src[:4])
	b := enc.Uint32(src[4:])
	w := len(c.key)
	for r := 0; r < w*4+32; r++ {
		a, b = b, b+(a+(b<<6^b>>8)+c.key[r%w]+uint32(r))
	}
	enc.PutUint32(dst[:4], a)
	enc.PutUint32(dst[4:], b)
}

func (c rtea) Decrypt(dst, src []byte) {
	a := enc.Uint32(src[:4])
	b := enc.Uint32(src[4:])
	w := len(c.key)
	for r := w*4 + 31; r >= 0; r-- {
		b, a = a, b-(a+(a<<6^a>>8)+c.key[r%w]+uint32(r))
	}
	enc.PutUint32(dst[:4], a)
	enc.PutUint32(dst[4:], b)
}
