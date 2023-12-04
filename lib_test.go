package negentropy

import (
	"fmt"
	"log"
	"testing"
)

func TestIfItRuns(t *testing.T) {
	na := NewNegentropy(50_000)
	na.Storage.Insert(0, [ID_SIZE]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	na.Storage.Insert(1, [ID_SIZE]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	na.Storage.Insert(3, [ID_SIZE]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	na.Storage.Seal()

	nb := NewNegentropy(50_000)
	nb.Storage.Insert(0, [ID_SIZE]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	nb.Storage.Insert(1, [ID_SIZE]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	nb.Storage.Insert(2, [ID_SIZE]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	nb.Storage.Insert(3, [ID_SIZE]byte{3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	nb.Storage.Seal()

	msg1, err := na.Initiate()
	if err != nil {
		log.Fatal(err)
		return
	}

	msg2, have, want, err := nb.Reconcile(msg1)
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Println("have", have)
	fmt.Println("want", want)

	msg3, have, want, err := na.Reconcile(msg2)
	if err != nil {
		log.Fatal(err)
		return
	}
	fmt.Println("have", have)
	fmt.Println("want", want)

	fmt.Println(msg3)
}
