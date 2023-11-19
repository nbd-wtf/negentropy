package negentropy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"

	"golang.org/x/exp/slices"
)

const (
	PROTOCOL_VERSION_0 = 0x60
	ID_SIZE            = 32
)

type Mode uint8

const (
	ModeSkip                       Mode = 0
	ModeFingerprint                Mode = 1
	ModeIdList                     Mode = 2
	ModeContinuation               Mode = 3
	ModeUnsupportedProtocolVersion Mode = 4
)

type Negentropy struct {
	frameSizeLimit     int
	addedItems         []Item
	pendingOutputs     []Output
	sealed             bool
	itemTimestamps     []uint64
	itemIds            []byte
	isInitiator        bool
	didHandshake       bool
	continuationNeeded bool
}

type Output struct {
	start   Item
	end     Item
	payload []byte
}

type Item struct {
	id        [ID_SIZE]byte
	timestamp uint64
}

type State struct {
	lastTimestampIn  uint64
	lastTimestampOut uint64
}

func NewNegentropy(idSize, frameSizeLimit int) (*Negentropy, error) {
	if frameSizeLimit != 0 && frameSizeLimit < 4096 {
		return nil, fmt.Errorf("frameSizeLimit too small")
	}

	n := &Negentropy{
		frameSizeLimit: frameSizeLimit,
		addedItems:     make([]Item, 0, 50),
		pendingOutputs: make([]Output, 0),
		sealed:         false,
		itemTimestamps: make([]uint64, 0),
		itemIds:        nil,
		isInitiator:    false,
		didHandshake:   false,
	}

	return n, nil
}

func (n *Negentropy) addItem(timestamp uint64, id [ID_SIZE]byte) error {
	if n.sealed {
		return fmt.Errorf("already sealed")
	}

	n.addedItems = append(n.addedItems, Item{id, timestamp})
	return nil
}

func (n *Negentropy) Seal() error {
	if n.sealed {
		return fmt.Errorf("already sealed")
	}
	n.sealed = true

	slices.SortFunc(n.addedItems, func(a, b Item) int {
		if a.timestamp < b.timestamp {
			return int(a.timestamp - b.timestamp)
		}
		return slices.Compare(a.id[:], b.id[:])
	})

	if len(n.addedItems) > 1 {
		for i := 0; i < len(n.addedItems)-1; i++ {
			if n.addedItems[i].timestamp == n.addedItems[i+1].timestamp &&
				slices.Compare(n.addedItems[i].id[:], n.addedItems[i+1].id[:]) > 0 {
				return fmt.Errorf("duplicate item inserted")
			}
		}
	}

	n.itemTimestamps = make([]uint64, len(n.addedItems))
	n.itemIds = make([]byte, len(n.addedItems)*ID_SIZE)

	for i := 0; i < len(n.addedItems); i++ {
		item := n.addedItems[i]
		n.itemTimestamps[i] = item.timestamp
		copy(n.itemIds[i*ID_SIZE:], item.id[:])
	}

	n.addedItems = nil
	return nil
}

func (n *Negentropy) Initiate() ([]byte, error) {
	if !n.sealed {
		return nil, fmt.Errorf("not sealed")
	}
	n.isInitiator = true
	if n.didHandshake {
		return nil, fmt.Errorf("can't initiate after reconcile")
	}

	err := n.splitRange(0, len(n.itemTimestamps), Item{}, Item{timestamp: math.MaxUint64}, &n.pendingOutputs)
	if err != nil {
		return nil, err
	}

	return n.buildOutput(true)
}

func (n *Negentropy) splitRange(
	lower, upper int,
	lowerBound, upperBound Item,
	outputs *[]Output,
) error {
	numElems := upper - lower
	buckets := 16

	if numElems < buckets*2 {
		var payload []byte
		payload = append(payload, encodeVarInt(int(ModeIdList))...)
		payload = append(payload, encodeVarInt(numElems)...)
		for it := lower; it < upper; it++ {
			itemAt := n.getItemId(it)
			payload = append(payload, itemAt[:]...)
		}

		*outputs = append(*outputs, Output{
			start:   Item{timestamp: lowerBound.timestamp, id: lowerBound.id},
			end:     Item{timestamp: upperBound.timestamp, id: upperBound.id},
			payload: payload,
		})
	} else {
		itemsPerBucket := numElems / buckets
		bucketsWithExtra := numElems % buckets
		curr := lower
		prevBound := n.getItem(curr)

		for i := 0; i < buckets; i++ {
			bucketSize := itemsPerBucket
			if i < bucketsWithExtra {
				bucketSize++
			}
			ourFingerprint := n.computeFingerprint(curr, bucketSize)
			curr += bucketSize

			var payload []byte
			payload = append(payload, encodeVarInt(int(ModeFingerprint))...)
			payload = append(payload, ourFingerprint[:]...)

			output := Output{
				payload: payload,
			}

			if i == 0 {
				output.start = lowerBound
			} else {
				output.start = prevBound
			}

			if curr == upper {
				output.end = upperBound
			} else {
				output.end = getMinimalItem(n.getItem(curr-1), n.getItem(curr))
			}

			*outputs = append(*outputs, output)

			prevBound = n.getItem(curr - 1)
		}

		(*outputs)[len(*outputs)-1].end = upperBound
	}

	return nil
}

func (n *Negentropy) findUpperBound(first, last int, value Item) int {
	count := last - first

	for count > 0 {
		it := first
		step := count / 2
		it += step

		itemAt := n.getItemId(it)
		if !(value.timestamp == n.getItemTimestamp(it) &&
			slices.Compare(value.id[:], itemAt[:]) < 0 ||
			value.timestamp < n.getItemTimestamp(it)) {
			first = it + 1
			count -= step + 1
		} else {
			count = step
		}
	}

	return first
}

func (n *Negentropy) Reconcile(query []byte) (
	[]byte,
	[][ID_SIZE]byte,
	[][ID_SIZE]byte,
	error,
) {
	var haveIds, needIds [][ID_SIZE]byte

	if !n.sealed {
		return nil, nil, nil, fmt.Errorf("not sealed")
	}
	n.continuationNeeded = false

	prevBound := Item{}
	prevIndex := 0
	state := State{}
	var outputs []Output

	if !n.isInitiator && !n.didHandshake {
		protocolVersion := arrayShift(&query)
		if protocolVersion < PROTOCOL_VERSION_0 || protocolVersion > PROTOCOL_VERSION_0+15 {
			return nil, nil, nil, fmt.Errorf("invalid negentropy protocol version byte")
		}
		if protocolVersion != PROTOCOL_VERSION_0 {
			o := make([]byte, 0, 300)
			o = append(o, encodeItem(Item{timestamp: PROTOCOL_VERSION_0}, &state)...)
			o = append(o, encodeVarInt(int(ModeUnsupportedProtocolVersion))...)
			return o, haveIds, needIds, nil
		}
		n.didHandshake = true
	}

	for len(query) != 0 {
		currBound := decodeItem(&query, &state)
		mode := decodeVarInt(&query)

		lower := prevIndex
		upper := n.findUpperBound(lower, len(n.itemTimestamps), currBound)

		switch mode {
		case int(ModeSkip):
			// Do nothing
		case int(ModeFingerprint):
			theirFingerprint := getBytes(&query, ID_SIZE)
			ourFingerprint := n.computeFingerprint(lower, upper-lower)

			if bytes.Compare(theirFingerprint, ourFingerprint[:]) != 0 {
				err := n.splitRange(lower, upper, prevBound, currBound, &outputs)
				if err != nil {
					return nil, nil, nil, err
				}
			}
		case int(ModeIdList):
			numIds := decodeVarInt(&query)
			theirElems := make(map[string][ID_SIZE]byte)

			for i := 0; i < numIds; i++ {
				e := getBytes(&query, ID_SIZE)
				theirElems[hex.EncodeToString(e)] = asStaticArray(e)
			}

			for i := lower; i < upper; i++ {
				k := n.getItemId(i)

				if _, exists := theirElems[hex.EncodeToString(k[:])]; !exists {
					// ID exists on our side, but not their side
					if n.isInitiator {
						haveIds = append(haveIds, k)
					}
				} else {
					// ID exists on both sides
					delete(theirElems, hex.EncodeToString(k[:]))
				}
			}

			if n.isInitiator {
				for _, v := range theirElems {
					needIds = append(needIds, v)
				}
			} else {
				responseHaveIds := make([][32]byte, 0)

				it := lower
				didSplit := false
				splitBound := Item{}
				flushIdListOutput := func() {
					payload := make([]byte, 0, 300)
					payload = append(payload, encodeVarInt(int(ModeIdList))...)

					payload = append(payload, encodeVarInt(len(responseHaveIds))...)
					for _, id := range responseHaveIds {
						payload = append(payload, id[:]...)
					}

					nextSplitBound := Item{timestamp: math.MaxUint64}
					if it+1 < upper {
						nextSplitBound = currBound
					}

					output := Output{
						end:     nextSplitBound,
						payload: payload,
					}

					if didSplit {
						output.start = splitBound
					} else {
						output.start = prevBound
					}

					outputs = append(outputs, output)

					splitBound = nextSplitBound
					didSplit = true

					responseHaveIds = make([][32]byte, 0)
				}

				for ; it < upper; it++ {
					responseHaveIds = append(responseHaveIds, n.getItemId(it))
					if len(responseHaveIds) >= 100 {
						// 100*32 is less than the minimum frame size limit of 4k
						flushIdListOutput()
					}
				}

				flushIdListOutput()
			}
		case int(ModeContinuation):
			n.continuationNeeded = true
		case int(ModeUnsupportedProtocolVersion):
			return nil, nil, nil, fmt.Errorf("server does not support our negentropy protocol version")
		default:
			return nil, nil, nil, fmt.Errorf("unexpected mode")
		}

		prevIndex = upper
		prevBound = currBound
	}

	for len(outputs) > 0 {
		n.pendingOutputs = append([]Output{outputs[len(outputs)-1]}, n.pendingOutputs...)
		outputs = outputs[:len(outputs)-1]
	}

	output, err := n.buildOutput(false)
	return output, haveIds, needIds, err
}

func (n *Negentropy) buildOutput(isInitialMessage bool) ([]byte, error) {
	output := make([]byte, 0, 300)
	currBound := Item{}
	state := State{}

	if isInitialMessage {
		if n.didHandshake {
			return nil, fmt.Errorf("already built initial message")
		}
		output = append(output, PROTOCOL_VERSION_0)
		n.didHandshake = true
	}

	slices.SortFunc(n.pendingOutputs, func(a, b Output) int {
		return itemCompare(a.start, b.start)
	})

	for len(n.pendingOutputs) > 0 {
		o := make([]byte, 0, 300)
		p := n.pendingOutputs[0]

		cmp := itemCompare(p.start, currBound)
		// if bounds are out of order or overlapping, finish and resume next time (shouldn't happen because of sort above)
		if cmp < 0 {
			break
		}

		if cmp != 0 {
			o = append(output, encodeItem(p.start, &state)...)
			o = append(output, encodeVarInt(int(ModeSkip))...)
		}
		o = append(output, encodeItem(p.end, &state)...)
		o = append(output, p.payload...)

		if n.frameSizeLimit > 0 && len(output)+len(o) > n.frameSizeLimit-5 {
			break // 5 leaves room for Continuation
		}
		output = append(output, o...)

		currBound = p.end
		n.pendingOutputs = n.pendingOutputs[1:]
	}

	// server indicates that it has more to send, OR ensure the client sends a non-empty message
	if !n.isInitiator && len(n.pendingOutputs) > 0 {
		output = append(output, encodeItem(Item{timestamp: math.MaxUint64}, &state)...)
		output = append(output, encodeVarInt(int(ModeContinuation))...)
	}

	if n.isInitiator && len(output) == 0 && !n.continuationNeeded {
		return nil, nil
	}

	return output, nil
}

func (n *Negentropy) computeFingerprint(lower int, num int) [ID_SIZE]byte {
	return sha256.Sum256(
		n.itemIds[lower*ID_SIZE : (lower+num)*ID_SIZE],
	)
}

func (n *Negentropy) getItem(i int) Item {
	return Item{
		timestamp: n.getItemTimestamp(i),
		id:        n.getItemId(i),
	}
}

func (n *Negentropy) getItemTimestamp(i int) uint64 {
	return n.itemTimestamps[i]
}

func (n *Negentropy) getItemId(i int) [ID_SIZE]byte {
	return asStaticArray(
		n.itemIds[i*ID_SIZE : (i+1)*ID_SIZE],
	)
}
