package negentropy

import (
	"crypto/sha256"
	"encoding/binary"
)

type Accumulator struct {
	buf []byte
}

func NewAccumulator() *Accumulator {
	acc := &Accumulator{}
	acc.SetToZero()
	return acc
}

func (acc *Accumulator) SetToZero() {
	acc.buf = make([]byte, ID_SIZE)
}

func (acc *Accumulator) Add(otherBuf []byte) {
	currCarry, nextCarry := 0, 0
	p := make([]byte, ID_SIZE)
	po := make([]byte, ID_SIZE)
	copy(p, acc.buf)
	copy(po, otherBuf)

	for i := 0; i < 8; i++ {
		offset := i * 4
		orig := binary.LittleEndian.Uint32(p[offset : offset+4])
		otherV := binary.LittleEndian.Uint32(po[offset : offset+4])

		next := orig + uint32(currCarry) + otherV
		if next > 0xFFFFFFFF {
			nextCarry = 1
		}

		binary.LittleEndian.PutUint32(p[offset:offset+4], next&0xFFFFFFFF)
		currCarry, nextCarry = nextCarry, 0
	}
}

func (acc *Accumulator) Negate() {
	p := make([]byte, ID_SIZE)
	copy(p, acc.buf)

	for i := 0; i < 8; i++ {
		offset := i * 4
		binary.LittleEndian.PutUint32(p[offset:offset+4], ^binary.LittleEndian.Uint32(p[offset:offset+4]))
	}

	one := make([]byte, ID_SIZE)
	one[0] = 1
	acc.Add(one)
}

func (acc *Accumulator) GetFingerprint(n int) []byte {
	hash := sha256.New()
	hash.Write(acc.buf)
	hash.Write(encodeVarInt(n))
	hashb := hash.Sum(nil)
	return hashb[:FINGERPRINT_SIZE]
}
