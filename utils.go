package negentropy

import (
	"fmt"
	"math"

	"golang.org/x/exp/slices"
)

func itemCompare(a, b Item) int {
	if a.timestamp == b.timestamp {
		return slices.Compare(a.id[:], b.id[:])
	}
	return int(a.timestamp) - int(b.timestamp)
}

func arrayShift(buf *[]byte) byte {
	*buf = (*buf)[1:]
	return (*buf)[0]
}

func arrayShiftN(buf *[]byte, n int) []byte {
	*buf = (*buf)[n:]
	return (*buf)[0:n]
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

func encodeTimestampOut(timestamp uint64, state *State) []byte {
	if timestamp == ^uint64(0)>>1 {
		state.lastTimestampOut = ^uint64(0) >> 1
		return encodeVarInt(0)
	}

	temp := timestamp
	timestamp -= state.lastTimestampOut
	state.lastTimestampOut = temp
	return encodeVarInt(int(timestamp) + 1)
}

func encodeItem(key Item, state *State) []byte {
	output := make([]byte, 0, 300)
	output = append(output, encodeTimestampOut(key.timestamp, state)...)
	output = append(output, encodeVarInt(len(key.id))...)
	output = append(output, key.id[:]...)

	return output
}

func decodeTimestampIn(encoded *[]byte, state *State) uint64 {
	timestamp := uint64(decodeVarInt(encoded))
	timestamp = timestamp - 1
	if state.lastTimestampIn == math.MaxUint64 {
		state.lastTimestampIn = math.MaxUint64
		return math.MaxUint64
	}
	timestamp += state.lastTimestampIn
	state.lastTimestampIn = timestamp
	return timestamp
}

func decodeItem(encoded *[]byte, state *State) Item {
	timestamp := decodeTimestampIn(encoded, state)
	length := decodeVarInt(encoded)
	if length > ID_SIZE {
		panic(fmt.Errorf("item key too long"))
	}
	id := getBytes(encoded, length)
	var idArr [ID_SIZE]byte
	copy(idArr[:], id)
	return Item{timestamp: timestamp, id: idArr}
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
