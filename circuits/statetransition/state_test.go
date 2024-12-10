package statetransition_test

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/statetransition"
	"github.com/vocdoni/vocdoni-z-sandbox/encrypt"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/tree/arbo"
)

func (o *State) oldVote(nullifier []byte) *encrypt.ElGamalCiphertext {
	data, err := o.dbTx.Get(nullifier)
	if err != nil {
		panic(err)
	}
	v := &encrypt.ElGamalCiphertext{}
	if err := v.Unmarshal(data); err != nil {
		panic(err)
	}
	return v
}

func (o *State) storeVote(nullifier []byte, vote *encrypt.ElGamalCiphertext) {
	data, err := vote.Marshal()
	if err != nil {
		panic(err)
	}
	if err := o.dbTx.Set(nullifier, data); err != nil {
		panic(err)
	}
}

// end absolute hack

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
	db        db.Database
	dbTx      db.WriteTx
	Witnesses statetransition.Circuit // witnesses for the snark circuit

	resultsAdd     *encrypt.ElGamalCiphertext
	resultsSub     *encrypt.ElGamalCiphertext
	ballotSum      *encrypt.ElGamalCiphertext
	overwriteSum   *encrypt.ElGamalCiphertext
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
	if err := tree.Add(KeyResultsAdd, encrypt.NewElGamalCiphertext().Hash()); err != nil {
		return State{}, err
	}
	if err := tree.Add(KeyResultsSub, encrypt.NewElGamalCiphertext().Hash()); err != nil {
		return State{}, err
	}

	o := State{
		db:         db,
		dbTx:       db.WriteTx(),
		tree:       tree,
		resultsAdd: encrypt.NewElGamalCiphertext(),
		resultsSub: encrypt.NewElGamalCiphertext(),
	}

	if err := o.StartBatch(); err != nil {
		return State{}, err
	}

	return o, nil
}

func (o *State) StartBatch() error {
	o.dbTx = o.db.WriteTx()

	o.Witnesses.NumNewVotes = 0
	o.Witnesses.NumOverwrites = 0
	o.Witnesses.AggregatedProof = 0
	o.ballotSum = encrypt.NewElGamalCiphertext()
	o.overwriteSum = encrypt.NewElGamalCiphertext()
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
	if _, _, err := o.tree.Get(v.nullifier); err == nil {
		o.overwriteSum.Add(o.overwriteSum, o.oldVote(v.nullifier))
		o.overwriteCount++
	}

	o.ballotSum.Add(o.ballotSum, v.elgamalBallot)
	o.ballotCount++

	o.votes = append(o.votes, v)

	o.storeVote(v.nullifier, v.elgamalBallot)
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
			o.Witnesses.Ballot[i].OldCiphertext = o.votes[i].elgamalBallot.ToGnark() // mock
			o.Witnesses.Ballot[i].MerkleTransition, err = statetransition.MerkleTransitionFromAddOrUpdate(o.tree,
				o.votes[i].nullifier, arbo.BigIntToBytesLE(32, &o.votes[i].ballot))
			o.Witnesses.Ballot[i].NewCiphertext = o.votes[i].elgamalBallot.ToGnark()
		} else {
			o.Witnesses.Ballot[i], err = statetransition.MerkleTransitionElGamalFromNoop(o.tree)
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
	o.Witnesses.ResultsAdd.OldCiphertext = o.resultsAdd.ToGnark()
	o.Witnesses.ResultsAdd.NewCiphertext = o.resultsAdd.Add(o.resultsAdd, o.ballotSum).ToGnark()
	o.Witnesses.ResultsAdd.MerkleTransition, err = statetransition.MerkleTransitionFromAddOrUpdate(o.tree,
		KeyResultsAdd, o.resultsAdd.Hash())
	if err != nil {
		return fmt.Errorf("ResultsAdd: %w", err)
	}

	// update ResultsSub
	o.Witnesses.ResultsSub.OldCiphertext = o.resultsSub.ToGnark()
	o.Witnesses.ResultsSub.NewCiphertext = o.resultsSub.Add(o.resultsSub, o.overwriteSum).ToGnark()
	o.Witnesses.ResultsSub.MerkleTransition, err = statetransition.MerkleTransitionFromAddOrUpdate(o.tree,
		KeyResultsSub, o.resultsSub.Hash())
	if err != nil {
		return fmt.Errorf("ResultsSub: %w", err)
	}

	// update stats
	o.Witnesses.NumNewVotes = o.ballotCount
	o.Witnesses.NumOverwrites = o.overwriteCount

	// RootHashAfter
	o.Witnesses.RootHashAfter, err = o.RootAsBigInt()
	if err != nil {
		return err
	}

	if err := o.dbTx.Commit(); err != nil {
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

// PlaintextVote describes a vote
type PlaintextVote struct {
	nullifier  []byte  // key
	ballot     big.Int // value
	address    []byte  // key
	commitment big.Int // value
}

// NewPlaintextVote creates a new vote
func NewPlaintextVote(nullifier, amount uint64) PlaintextVote {
	var v PlaintextVote
	v.nullifier = arbo.BigIntToBytesLE(statetransition.MaxKeyLen,
		big.NewInt(int64(nullifier)+int64(KeyNullifiersOffset))) // mock
	v.ballot.SetUint64(amount)

	v.address = arbo.BigIntToBytesLE(statetransition.MaxKeyLen,
		big.NewInt(int64(nullifier)+int64(KeyAddressesOffset))) // mock
	v.commitment.SetUint64(amount + 256) // mock
	return v
}

// Vote describes a vote with homomorphic ballot
type Vote struct {
	nullifier     []byte                     // key
	ballot        big.Int                    // value
	elgamalBallot *encrypt.ElGamalCiphertext // test
	address       []byte                     // key
	commitment    big.Int                    // value
}

// NewVote creates a new vote
func NewVote(nullifier, amount uint64) Vote {
	var v Vote
	v.nullifier = arbo.BigIntToBytesLE(statetransition.MaxKeyLen,
		big.NewInt(int64(nullifier)+int64(KeyNullifiersOffset))) // mock

	v.ballot.SetUint64(amount) // debug

	v.elgamalBallot = NewEncryptedBallot(amount)

	v.address = arbo.BigIntToBytesLE(statetransition.MaxKeyLen,
		big.NewInt(int64(nullifier)+int64(KeyAddressesOffset))) // mock
	v.commitment.SetUint64(amount + 256) // mock
	return v
}

// NewEncryptedBallot creates a new EncryptedBallot
func NewEncryptedBallot(amount uint64) *encrypt.ElGamalCiphertext {
	// generate a public mocked key
	_, pubKey := generateKeyPair()

	// and a random k to encrypt first message
	k1, err := randomK()
	if err != nil {
		panic(fmt.Errorf("Error generating random k: %v", err))
	}
	// encrypt a simple message (mock current Results)
	msg1 := big.NewInt(int64(amount))
	return encrypt.NewElGamalCiphertext().Encrypt(msg1, pubKey, k1)
}

func randomK() (*big.Int, error) {
	// Generate random scalar k
	kBytes := make([]byte, 32)
	_, err := rand.Read(kBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random k: %v", err)
	}

	k := new(big.Int).SetBytes(kBytes)
	k.Mod(k, babyjub.SubOrder)
	return k, nil
}

func generateKeyPair() (babyjub.PrivateKey, *babyjub.PublicKey) {
	privkey := babyjub.NewRandPrivKey()
	return privkey, privkey.Public()
}
