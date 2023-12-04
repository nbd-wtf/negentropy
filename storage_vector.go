package negentropy

import (
	"fmt"

	"golang.org/x/exp/slices"
)

type NegentropyStorageVector struct {
	items  []Item
	sealed bool
}

func (nsv *NegentropyStorageVector) Insert(timestamp uint32, id [ID_SIZE]byte) {
	if nsv.sealed {
		panic(fmt.Errorf("already sealed"))
	}
	nsv.items = append(nsv.items, Item{timestamp: timestamp, id: id})
}

func (nsv *NegentropyStorageVector) Seal() {
	if nsv.sealed {
		panic(fmt.Errorf("already sealed"))
	}
	nsv.sealed = true

	slices.SortFunc(nsv.items, func(a, b Item) int {
		if a.timestamp == b.timestamp {
			return slices.Compare(a.id[:], b.id[:])
		}
		return int(a.timestamp - b.timestamp)
	})
	for i := 1; i < len(nsv.items); i++ {
		if itemCompare(nsv.items[i-1], nsv.items[i]) == 0 {
			panic(fmt.Errorf("duplicate Item inserted"))
		}
	}
}

func (nsv *NegentropyStorageVector) Unseal() {
	nsv.sealed = false
}

func (nsv *NegentropyStorageVector) Size() int {
	nsv.checkSealed()
	return len(nsv.items)
}

func (nsv *NegentropyStorageVector) GetItem(i int) Item {
	nsv.checkSealed()
	return nsv.items[i]
}

func (nsv *NegentropyStorageVector) Iterate(begin, end int, cb func(Item) bool) {
	nsv.checkSealed()
	nsv.checkBounds(begin, end)

	for i := begin; i < end; i++ {
		if !cb(nsv.items[i]) {
			break
		}
	}
}

func (nsv *NegentropyStorageVector) FindLowerBound(begin, end int, bound Item) int {
	nsv.checkSealed()
	nsv.checkBounds(begin, end)
	v, ok := slices.BinarySearchFunc(nsv.items[begin:], end, func(a Item, _ int) int {
		return itemCompare(a, bound)
	})
	if !ok {
		fmt.Println("not found in slice")
	}
	return v
}

func (nsv *NegentropyStorageVector) Fingerprint(begin, end int) []byte {
	out := NewAccumulator()
	out.SetToZero()

	nsv.Iterate(begin, end, func(item Item) bool {
		out.Add(item.id[:])
		return true
	})

	return out.GetFingerprint(end - begin)
}

func (nsv *NegentropyStorageVector) checkSealed() {
	if !nsv.sealed {
		panic(fmt.Errorf("not sealed"))
	}
}

func (nsv *NegentropyStorageVector) checkBounds(begin, end int) {
	if begin > end || end > len(nsv.items) {
		panic(fmt.Errorf("bad range: %d > %d || %d > %d", begin, end, end, len(nsv.items)))
	}
}
