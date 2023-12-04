package negentropy

import (
	"fmt"
	"math"

	"golang.org/x/exp/slices"
)

type Negentropy struct {
	Storage          *NegentropyStorageVector
	frameSizeLimit   uint
	lastTimestampIn  uint32
	lastTimestampOut uint32
	isInitiator      bool
}

func NewNegentropy(frameSizeLimit uint) *Negentropy {
	if frameSizeLimit != 0 && frameSizeLimit < 4096 {
		panic(fmt.Errorf("frameSizeLimit too small"))
	}

	storage := &NegentropyStorageVector{
		items:  make([]Item, 0, 36),
		sealed: false,
	}

	return &Negentropy{
		Storage:          storage,
		frameSizeLimit:   frameSizeLimit,
		lastTimestampIn:  0,
		lastTimestampOut: 0,
		isInitiator:      false,
	}
}

func (ngtp *Negentropy) Initiate() ([]byte, error) {
	if ngtp.isInitiator {
		return nil, fmt.Errorf("already initiated")
	}
	ngtp.isInitiator = true

	output := make([]byte, 0, 120)
	output = append(output, PROTOCOL_VERSION)
	ngtp.splitRange(0, ngtp.Storage.Size(), Item{timestamp: ^uint32(0) >> 1}, &output)

	return output, nil
}

func (ngtp *Negentropy) Reconcile(query []byte) (output []byte, haveIds, needIds [][ID_SIZE]byte, err error) {
	fullOutput := make([]byte, 0, 120)
	fullOutput = append(fullOutput, PROTOCOL_VERSION)

	queryBuf := make([]byte, len(query))
	copy(queryBuf, query)

	protocolVersion := arrayShift(&queryBuf)
	if protocolVersion < 0x60 || protocolVersion > 0x6F {
		return nil, nil, nil, fmt.Errorf("invalid negentropy protocol version byte: %d", protocolVersion)
	}
	if protocolVersion != PROTOCOL_VERSION {
		if ngtp.isInitiator {
			return fullOutput, haveIds, needIds, fmt.Errorf("unsupported negentropy protocol version requested: " + string(rune(protocolVersion-0x60)))
		} else {
			return fullOutput, haveIds, needIds, nil
		}
	}

	storageSize := ngtp.Storage.Size()
	prevBound := Item{timestamp: 0}
	prevIndex := 0
	skip := false

	for len(queryBuf) != 0 {
		o := make([]byte, 0, 120)

		doSkip := func() {
			if skip {
				o = append(o, ngtp.encodeItem(prevBound)...)
				o = append(o, encodeVarInt(int(ModeSkip))...)
			}
		}

		currBound := ngtp.decodeItem(&queryBuf)
		mode := Mode(decodeVarInt(&queryBuf))

		lower := prevIndex
		upper := ngtp.Storage.FindLowerBound(prevIndex, storageSize, currBound)

		if mode == ModeSkip {
			skip = true
		} else if mode == ModeFingerprint {
			theirFingerprint := getBytes(&queryBuf, FINGERPRINT_SIZE)
			ourFingerprint := ngtp.Storage.Fingerprint(lower, upper)

			if slices.Compare(theirFingerprint, ourFingerprint) != 0 {
				doSkip()
				ngtp.splitRange(lower, upper, currBound, &o)
			} else {
				skip = true
			}
		} else if mode == ModeIdList {
			numIds := decodeVarInt(&queryBuf)

			theirElems := make(map[string][]byte)
			for i := 0; i < numIds; i++ {
				e := getBytes(&queryBuf, ID_SIZE)
				theirElems[string(e)] = e
			}

			ngtp.Storage.Iterate(lower, upper, func(item Item) bool {
				k := item.id[:]

				if _, ok := theirElems[string(k)]; !ok {
					// ID exists on our side, but not their side
					if ngtp.isInitiator {
						haveIds = append(haveIds, asStaticArray(k))
					}
				} else {
					// ID exists on both sides
					delete(theirElems, string(k))
				}

				return true
			})

			if ngtp.isInitiator {
				skip = true

				for _, v := range theirElems {
					// ID exists on their side, but not our side
					needIds = append(needIds, asStaticArray(v))
				}
			} else {
				doSkip()

				responseIds := make([]byte, 0, 120)
				numResponseIds := 0
				endBound := currBound

				ngtp.Storage.Iterate(lower, upper, func(item Item) bool {
					if ngtp.exceededFrameSizeLimit(len(fullOutput) + len(responseIds)) {
						endBound = Item{timestamp: item.timestamp, id: item.id}
						upper = prevIndex // shrink upper so that the remaining range gets the correct fingerprint
						return false
					}

					responseIds = append(responseIds, item.id[:]...)
					numResponseIds++
					return true
				})

				o = append(o, ngtp.encodeItem(endBound)...)
				o = append(o, encodeVarInt(int(ModeIdList))...)
				o = append(o, encodeVarInt(numResponseIds)...)
				o = append(o, responseIds...)
				fullOutput = append(fullOutput, o...)
			}
		} else {
			return fullOutput, haveIds, needIds, fmt.Errorf("unexpected mode")
		}

		if ngtp.exceededFrameSizeLimit(len(fullOutput) + len(o)) {
			remainingFingerprint := ngtp.Storage.Fingerprint(upper, storageSize)
			fullOutput = append(fullOutput, ngtp.encodeItem(Item{timestamp: ^uint32(0) >> 1})...)
			fullOutput = append(fullOutput, encodeVarInt(int(ModeFingerprint))...)
			fullOutput = append(fullOutput, remainingFingerprint...)
			break
		} else {
			fullOutput = append(fullOutput, o...)
		}

		prevIndex = upper
		prevBound = currBound
	}

	return fullOutput, haveIds, needIds, nil
}

func (ngtp *Negentropy) splitRange(lower int, upper int, upperBound Item, o *[]byte) {
	numElems := upper - lower
	buckets := 16

	buf := *o
	defer func() {
		*o = buf
	}()

	if numElems < buckets*2 {
		buf = append(buf, ngtp.encodeItem(upperBound)...)
		buf = append(buf, encodeVarInt(ModeIdList)...)
		buf = append(buf, encodeVarInt(numElems)...)

		ngtp.Storage.Iterate(lower, upper, func(item Item) bool {
			buf = append(buf, item.id[:]...)
			return true
		})
	} else {
		itemsPerBucket := int(math.Floor(float64(numElems) / float64(buckets)))
		bucketsWithExtra := numElems % buckets
		curr := lower

		for i := 0; i < buckets; i++ {
			bucketSize := itemsPerBucket
			if i < bucketsWithExtra {
				bucketSize++
			}

			ourFingerprint := ngtp.Storage.Fingerprint(curr, curr+bucketSize)
			curr += bucketSize

			nextBound := upperBound
			if curr != upper {
				nextBound = getMinimalItem(ngtp.Storage.GetItem(curr-1), ngtp.Storage.GetItem(curr))
			}

			buf = append(buf, ngtp.encodeItem(nextBound)...)
			buf = append(buf, encodeVarInt(ModeFingerprint)...)
			buf = append(buf, ourFingerprint...)
		}
	}
}

func (ngtp *Negentropy) exceededFrameSizeLimit(n int) bool {
	if ngtp.frameSizeLimit == 0 {
		return false
	}
	return uint(n) > ngtp.frameSizeLimit-200
}

func (ngtp *Negentropy) encodeTimestampOut(timestamp uint32) []byte {
	if timestamp == ^uint32(0)>>1 {
		ngtp.lastTimestampOut = ^uint32(0) >> 1
		return encodeVarInt(0)
	}

	temp := timestamp
	timestamp -= ngtp.lastTimestampOut
	ngtp.lastTimestampOut = temp
	return encodeVarInt(int(timestamp) + 1)
}

func (ngtp *Negentropy) encodeItem(key Item) []byte {
	output := make([]byte, 0, 300)
	output = append(output, ngtp.encodeTimestampOut(key.timestamp)...)
	output = append(output, encodeVarInt(len(key.id))...)
	output = append(output, key.id[:]...)

	return output
}

func (ngtp *Negentropy) decodeTimestampIn(encoded *[]byte) uint32 {
	timestamp := uint32(decodeVarInt(encoded))
	timestamp = timestamp - 1
	if ngtp.lastTimestampIn == math.MaxUint32 {
		ngtp.lastTimestampIn = math.MaxUint32
		return math.MaxUint32
	}
	timestamp += ngtp.lastTimestampIn
	ngtp.lastTimestampIn = timestamp
	return timestamp
}

func (ngtp *Negentropy) decodeItem(encoded *[]byte) Item {
	timestamp := ngtp.decodeTimestampIn(encoded)
	length := decodeVarInt(encoded)
	if length > ID_SIZE {
		panic(fmt.Errorf("item key too long"))
	}
	id := getBytes(encoded, length)
	var idArr [ID_SIZE]byte
	copy(idArr[:], id)
	return Item{timestamp: timestamp, id: idArr}
}
