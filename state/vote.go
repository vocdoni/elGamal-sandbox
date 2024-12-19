package state

import (
	"fmt"
	"math/big"

	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
)

// Vote describes a vote with homomorphic ballot
type Vote struct {
	Nullifier  []byte
	Ballot     *elgamal.Ciphertexts
	Address    []byte
	Commitment *big.Int
}

// AddVote adds a vote to the state
//   - if nullifier exists, it counts as vote overwrite
func (o *State) AddVote(v *Vote) error {
	if o.dbTx == nil {
		return fmt.Errorf("need to StartBatch() first")
	}
	if len(o.votes) >= VoteBatchSize {
		return fmt.Errorf("too many votes for this batch")
	}

	// if nullifier exists, it's a vote overwrite, need to count the overwritten vote
	// so it's later added to circuit.ResultsSub
	if _, value, err := o.tree.Get(v.Nullifier); err == nil {
		oldVote := elgamal.NewCiphertexts(Curve)
		if err := oldVote.Deserialize(value); err != nil {
			return err
		}
		o.OverwriteSum.Add(o.OverwriteSum, oldVote)
		o.overwriteCount++
	}

	o.BallotSum.Add(o.BallotSum, v.Ballot)
	o.ballotCount++

	o.votes = append(o.votes, v)
	return nil
}
