package statetransition_test

import (
	"fmt"

	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/statetransition"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
)

func GenerateWitnesses(o *state.State) (*statetransition.Circuit, error) {
	var err error
	witness := &statetransition.Circuit{}

	// TODO: mock, replace by actual AggregatedProof
	witness.AggregatedProof = 0

	// RootHashBefore
	witness.RootHashBefore, err = o.RootAsBigInt()
	if err != nil {
		return nil, err
	}

	// first get MerkleProofs, since they need to belong to RootHashBefore, i.e. before MerkleTransitions
	if witness.ProcessID, err = o.GenMerkleProof(state.KeyProcessID); err != nil {
		return nil, err
	}
	if witness.CensusRoot, err = o.GenMerkleProof(state.KeyCensusRoot); err != nil {
		return nil, err
	}
	if witness.BallotMode, err = o.GenMerkleProof(state.KeyBallotMode); err != nil {
		return nil, err
	}
	if witness.EncryptionKey, err = o.GenMerkleProof(state.KeyEncryptionKey); err != nil {
		return nil, err
	}

	// now build ordered chain of MerkleTransitions

	// add Ballots
	for i := range witness.Ballot {
		if i < len(o.Votes()) {
			witness.Ballot[i], err = o.MerkleTransitionFromAddOrUpdate(
				o.Votes()[i].Nullifier, o.Votes()[i].Ballot.Serialize())
		} else {
			witness.Ballot[i], err = o.MerkleTransitionFromNoop()
		}
		if err != nil {
			return nil, err
		}
	}

	// add Commitments
	for i := range witness.Commitment {
		if i < len(o.Votes()) {
			witness.Commitment[i], err = o.MerkleTransitionFromAddOrUpdate(
				o.Votes()[i].Address, arbo.BigIntToBytes(32, o.Votes()[i].Commitment))
		} else {
			witness.Commitment[i], err = o.MerkleTransitionFromNoop()
		}
		if err != nil {
			return nil, err
		}
	}

	// update ResultsAdd
	witness.ResultsAdd, err = o.MerkleTransitionFromAddOrUpdate(
		state.KeyResultsAdd, o.ResultsAdd.Add(o.ResultsAdd, o.BallotSum).Serialize())
	if err != nil {
		return nil, fmt.Errorf("ResultsAdd: %w", err)
	}

	// update ResultsSub
	witness.ResultsSub, err = o.MerkleTransitionFromAddOrUpdate(
		state.KeyResultsSub, o.ResultsSub.Add(o.ResultsSub, o.OverwriteSum).Serialize())
	if err != nil {
		return nil, fmt.Errorf("ResultsSub: %w", err)
	}

	// update stats
	witness.NumNewVotes = o.BallotCount()
	witness.NumOverwrites = o.OverwriteCount()

	// RootHashAfter
	witness.RootHashAfter, err = o.RootAsBigInt()
	if err != nil {
		return nil, err
	}

	return witness, nil
}
