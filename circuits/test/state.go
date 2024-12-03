package test

import (
	"fmt"
	"math/big"

	"github.com/vocdoni/vocdoni-z-sandbox/circuits/statetransition"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/tree/arbo"
)

var hashFunc = arbo.HashFunctionPoseidon

var (
	KeyProcessID     = []byte{0x00}
	KeyCensusRoot    = []byte{0x01}
	KeyBallotMode    = []byte{0x02}
	KeyEncryptionKey = []byte{0x03}
	KeyResultsAdd    = []byte{0x04}
	KeyResultsSub    = []byte{0x05}

	KeyNullifiersOffset = 100 // mock, should really be a prefix, not an offset
	KeyAddressesOffset  = 200 // mock, should really be a prefix, not an offsest
)

// State represents a state tree
type State struct {
	tree      *arbo.Tree
	Witnesses statetransition.Circuit // witnesses for the snark circuit

	resultsAdd     *big.Int
	resultsSub     *big.Int
	ballotSum      *big.Int
	overwriteSum   *big.Int
	ballotCount    int
	overwriteCount int
	votes          []Vote
}

// New creates a new State, initialized with the passed parameters.
func NewState(db db.Database, processID, censusRoot, ballotMode, encryptionKey []byte) (State, error) {
	tree, err := arbo.NewTree(arbo.Config{
		Database: db, MaxLevels: statetransition.MaxLevels,
		HashFunction: hashFunc,
	})
	if err != nil {
		return State{}, err
	}

	if err := tree.Add(KeyProcessID, processID); err != nil {
		return State{}, err
	}
	if err := tree.Add(KeyCensusRoot, censusRoot); err != nil {
		return State{}, err
	}
	if err := tree.Add(KeyBallotMode, ballotMode); err != nil {
		return State{}, err
	}
	if err := tree.Add(KeyEncryptionKey, encryptionKey); err != nil {
		return State{}, err
	}
	if err := tree.Add(KeyResultsAdd, []byte{0x00}); err != nil {
		return State{}, err
	}
	if err := tree.Add(KeyResultsSub, []byte{0x00}); err != nil {
		return State{}, err
	}

	o := State{
		tree: tree,
	}

	if err := o.StartBatch(); err != nil {
		return State{}, err
	}

	return o, nil
}

func (o *State) StartBatch() error {
	o.Witnesses.NumNewVotes = 0
	o.Witnesses.NumOverwrites = 0
	o.Witnesses.AggregatedProof = 0
	if o.resultsAdd == nil {
		o.resultsAdd = big.NewInt(0)
	}
	if o.resultsSub == nil {
		o.resultsSub = big.NewInt(0)
	}
	o.ballotSum = big.NewInt(0)
	o.overwriteSum = big.NewInt(0)
	o.ballotCount = 0
	o.overwriteCount = 0
	o.votes = []Vote{}

	var err error
	if o.Witnesses.ProcessID, err = statetransition.GenMerkleProof(o.tree, KeyProcessID); err != nil {
		return err
	}
	if o.Witnesses.CensusRoot, err = statetransition.GenMerkleProof(o.tree, KeyCensusRoot); err != nil {
		return err
	}
	if o.Witnesses.BallotMode, err = statetransition.GenMerkleProof(o.tree, KeyBallotMode); err != nil {
		return err
	}
	if o.Witnesses.EncryptionKey, err = statetransition.GenMerkleProof(o.tree, KeyEncryptionKey); err != nil {
		return err
	}
	return nil
}

// AddVote adds a vote to the state
//   - if nullifier exists, it counts as vote overwrite
//
// TODO: use Tx to rollback in case of failure
func (o *State) AddVote(v Vote) error {
	if len(o.votes) >= statetransition.VoteBatchSize {
		return fmt.Errorf("too many votes for this batch")
	}

	// if nullifier exists, it's a vote overwrite, need to count the overwritten vote
	// so it's later added to circuit.ResultsSub
	if _, v, err := o.tree.Get(v.nullifier); err == nil {
		o.overwriteSum = o.overwriteSum.Add(o.overwriteSum, arbo.BytesLEToBigInt(v))
		o.overwriteCount++
	}

	o.ballotSum = o.ballotSum.Add(o.ballotSum, &v.ballot)
	o.ballotCount++

	o.votes = append(o.votes, v)
	return nil
}

func (o *State) EndBatch() error {
	// now build ordered chain of MerkleTransitions
	var err error

	// RootHashBefore
	o.Witnesses.RootHashBefore, err = o.RootAsBigInt()
	if err != nil {
		return err
	}

	// add Ballots
	for i := range o.Witnesses.Ballot {
		if i < len(o.votes) {
			o.Witnesses.Ballot[i], err = statetransition.MerkleTransitionFromAddOrUpdate(o.tree,
				o.votes[i].nullifier, arbo.BigIntToBytesLE(32, &o.votes[i].ballot))
		} else {
			o.Witnesses.Ballot[i], err = statetransition.MerkleTransitionFromNoop(o.tree)
		}
		if err != nil {
			return err
		}
	}

	// add Commitments
	for i := range o.Witnesses.Commitment {
		if i < len(o.votes) {
			o.Witnesses.Commitment[i], err = statetransition.MerkleTransitionFromAddOrUpdate(o.tree,
				o.votes[i].address, arbo.BigIntToBytesLE(32, &o.votes[i].commitment))
		} else {
			o.Witnesses.Commitment[i], err = statetransition.MerkleTransitionFromNoop(o.tree)
		}
		if err != nil {
			return err
		}
	}

	// update ResultsAdd
	o.Witnesses.ResultsAdd, err = statetransition.MerkleTransitionFromAddOrUpdate(o.tree,
		KeyResultsAdd, arbo.BigIntToBytesLE(32, o.resultsAdd.Add(o.resultsAdd, o.ballotSum)))
	if err != nil {
		return err
	}

	// update ResultsSub
	o.Witnesses.ResultsSub, err = statetransition.MerkleTransitionFromAddOrUpdate(o.tree,
		KeyResultsSub, arbo.BigIntToBytesLE(32, o.resultsSub.Add(o.resultsSub, o.overwriteSum)))
	if err != nil {
		return err
	}

	// update stats
	o.Witnesses.NumNewVotes = o.ballotCount
	o.Witnesses.NumOverwrites = o.overwriteCount

	// RootHashAfter
	o.Witnesses.RootHashAfter, err = o.RootAsBigInt()
	if err != nil {
		return err
	}

	return nil
}

func (o *State) RootAsBigInt() (*big.Int, error) {
	root, err := o.tree.Root()
	if err != nil {
		return nil, err
	}
	return arbo.BytesLEToBigInt(root), nil
}

// Vote describes a vote
type Vote struct {
	nullifier  []byte  // key
	ballot     big.Int // value
	address    []byte  // key
	commitment big.Int // value
}

// NewVote creates a new vote
func NewVote(nullifier, amount uint64) Vote {
	var v Vote
	v.nullifier = arbo.BigIntToBytesLE(statetransition.MaxKeyLen,
		big.NewInt(int64(nullifier)+int64(KeyNullifiersOffset))) // mock
	v.ballot.SetUint64(amount)

	v.address = arbo.BigIntToBytesLE(statetransition.MaxKeyLen,
		big.NewInt(int64(nullifier)+int64(KeyAddressesOffset))) // mock
	v.commitment.SetUint64(amount + 256) // mock
	return v
}
