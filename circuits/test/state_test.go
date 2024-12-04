package test

import (
	"testing"

	"go.vocdoni.io/dvote/db/metadb"
)

func TestVoteBatch(t *testing.T) {
	state, err := NewState(metadb.NewTest(t),
		[]byte{0xca, 0xfe, 0x00},
		[]byte{0xca, 0xfe, 0x01},
		[]byte{0xca, 0xfe, 0x02},
		[]byte{0xca, 0xfe, 0x03},
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := state.StartBatch(); err != nil {
		t.Fatal(err)
	}
	if err := state.AddVote(NewVote(1, 16)); err != nil {
		t.Fatal(err)
	}
	if err := state.EndBatch(); err != nil {
		t.Fatal(err)
	}
}
