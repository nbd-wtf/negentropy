package negentropy

import (
	"golang.org/x/exp/slices"
)

func itemCompare(a, b Item) int {
	if a.timestamp == b.timestamp {
		return slices.Compare(a.id[:], b.id[:])
	}
	return int(a.timestamp) - int(b.timestamp)
}

func arrayShift(buf *[]byte) byte {
	v := (*buf)[0]
	*buf = (*buf)[1:]
	return v
}

func arrayShiftN(buf *[]byte, n int) []byte {
	v := (*buf)[0:n]
	*buf = (*buf)[n:]
	return v
}

func getBytes(buf *[]byte, n int) []byte {
	if len(*buf) < n {
		return nil
	}
	return arrayShiftN(buf, n)
}

func decodeVarInt(buf *[]byte) int {
	res := 0

	for {
		if len(*buf) == 0 {
			return -1
		}
		byteVal := arrayShift(buf)
		res = (res << 7) | (int(byteVal) & 127)
		if (byteVal & 128) == 0 {
			break
		}
	}

	return res
}

func encodeVarInt(value int) []byte {
	if value == 0 {
		return []byte{0}
	}

	o := make([]byte, 0, 8)
	for value != 0 {
		o = append(o, byte(value&127))
		value >>= 7
	}

	slices.Reverse(o)
	for i := 0; i < len(o)-1; i++ {
		o[i] |= 128
	}

	return o
}

func getMinimalItem(prev, curr Item) Item {
	if curr.timestamp != prev.timestamp {
		return Item{timestamp: curr.timestamp}
	} else {
		sharedPrefixBytes := 0

		for i := 0; i < ID_SIZE; i++ {
			if curr.id[i] != prev.id[i] {
				break
			}
			sharedPrefixBytes++
		}

		return Item{
			timestamp: curr.timestamp,
			id:        asStaticArray(curr.id[:sharedPrefixBytes+1]),
		}
	}
}

func asStaticArray(bs []byte) [ID_SIZE]byte {
	var b [ID_SIZE]byte
	copy(b[:], bs)
	return b
}
