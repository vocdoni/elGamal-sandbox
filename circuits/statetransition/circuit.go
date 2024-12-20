package statetransition

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/elgamal"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

var HashFn = utils.MiMCHasher

const (
	// votes that were processed in AggregatedProof
	VoteBatchSize = 10
)

type Circuit struct {
	// ---------------------------------------------------------------------------------------------
	// PUBLIC INPUTS

	// list of root hashes
	RootHashBefore frontend.Variable `gnark:",public"`
	RootHashAfter  frontend.Variable `gnark:",public"`
	NumNewVotes    frontend.Variable `gnark:",public"`
	NumOverwrites  frontend.Variable `gnark:",public"`

	// ---------------------------------------------------------------------------------------------
	// SECRET INPUTS

	AggregatedProof frontend.Variable // mock, this should be a zkProof

	ProcessID     state.MerkleProof
	CensusRoot    state.MerkleProof
	BallotMode    state.MerkleProof
	EncryptionKey state.MerkleProof
	ResultsAdd    state.MerkleTransition
	ResultsSub    state.MerkleTransition
	Ballot        [VoteBatchSize]state.MerkleTransition
	Commitment    [VoteBatchSize]state.MerkleTransition
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	circuit.VerifyAggregatedZKProof(api)
	circuit.VerifyMerkleProofs(api, HashFn)
	circuit.VerifyMerkleTransitions(api, HashFn)
	circuit.VerifyBallots(api)
	return nil
}

func (circuit Circuit) VerifyAggregatedZKProof(api frontend.API) {
	// all of the following values compose the preimage that is hashed
	// to produce the public input needed to verify AggregatedProof.
	// they are extracted from the MerkleProofs:
	// ProcessID     := circuit.ProcessID.Value
	// CensusRoot    := circuit.CensusRoot.Value
	// BallotMode    := circuit.BallotMode.Value
	// EncryptionKey := circuit.EncryptionKey.Value
	// Nullifiers    := circuit.Ballot[i].NewKey
	// Ballots       := circuit.Ballot[i].NewValue
	// Addressess    := circuit.Commitment[i].NewKey
	// Commitments   := circuit.Commitment[i].NewValue

	api.Println("verify AggregatedZKProof mock:", circuit.AggregatedProof) // mock

	packedInputs := func() frontend.Variable {
		for i, p := range []state.MerkleProof{
			circuit.ProcessID,
			circuit.CensusRoot,
			circuit.BallotMode,
			circuit.EncryptionKey,
		} {
			api.Println("packInputs mock", i, p.Value) // mock
		}
		for i := range circuit.Ballot {
			api.Println("packInputs mock nullifier", i, circuit.Ballot[i].NewKey) // mock
			api.Println("packInputs mock ballot", i, circuit.Ballot[i].NewValue)  // mock
		}
		for i := range circuit.Commitment {
			api.Println("packInputs mock address", i, circuit.Commitment[i].NewKey)      // mock
			api.Println("packInputs mock commitment", i, circuit.Commitment[i].NewValue) // mock
		}
		return 1 // mock, should return hash of packed inputs
	}

	api.AssertIsEqual(packedInputs(), 1) // TODO: mock, should actually verify AggregatedZKProof
}

func (circuit Circuit) VerifyMerkleProofs(api frontend.API, hFn utils.Hasher) {
	api.Println("verify ProcessID, CensusRoot, BallotMode and EncryptionKey belong to RootHashBefore")
	circuit.ProcessID.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.CensusRoot.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.BallotMode.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.EncryptionKey.VerifyProof(api, hFn, circuit.RootHashBefore)
}

func (circuit Circuit) VerifyMerkleTransitions(api frontend.API, hFn utils.Hasher) {
	// verify chain of tree transitions, order here is fundamental.
	api.Println("tree transition starts with RootHashBefore:", util.PrettyHex(circuit.RootHashBefore))
	root := circuit.RootHashBefore
	for i := range circuit.Ballot {
		root = circuit.Ballot[i].Verify(api, hFn, root)
	}
	for i := range circuit.Commitment {
		root = circuit.Commitment[i].Verify(api, hFn, root)
	}
	root = circuit.ResultsAdd.Verify(api, hFn, root)
	root = circuit.ResultsSub.Verify(api, hFn, root)
	api.Println("and final root is", util.PrettyHex(root), "should be equal to RootHashAfter", util.PrettyHex(circuit.RootHashAfter))
	api.AssertIsEqual(root, circuit.RootHashAfter)
}

// VerifyBallots counts the ballots using homomorphic encrpytion
func (circuit Circuit) VerifyBallots(api frontend.API) {
	ballotSum, overwrittenSum, zero := elgamal.NewCiphertexts(), elgamal.NewCiphertexts(), elgamal.NewCiphertexts()
	var ballotCount, overwrittenCount frontend.Variable = 0, 0

	for _, b := range circuit.Ballot {
		// TODO: check that Hash(NewCiphertext) matches b.NewValue
		// and Hash(OldCiphertext) matches b.OldValue
		ballotSum.Add(api, ballotSum,
			elgamal.NewCiphertexts().Select(api, b.IsInsertOrUpdate(api), &b.NewCiphertexts, zero))

		overwrittenSum.Add(api, overwrittenSum,
			elgamal.NewCiphertexts().Select(api, b.IsUpdate(api), &b.OldCiphertexts, zero))

		ballotCount = api.Add(ballotCount, api.Select(b.IsInsertOrUpdate(api), 1, 0))
		overwrittenCount = api.Add(overwrittenCount, api.Select(b.IsUpdate(api), 1, 0))
	}

	circuit.ResultsAdd.NewCiphertexts.AssertIsEqual(api,
		circuit.ResultsAdd.OldCiphertexts.Add(api, &circuit.ResultsAdd.OldCiphertexts, ballotSum))
	circuit.ResultsSub.NewCiphertexts.AssertIsEqual(api,
		circuit.ResultsSub.OldCiphertexts.Add(api, &circuit.ResultsSub.OldCiphertexts, overwrittenSum))
	api.AssertIsEqual(circuit.NumNewVotes, ballotCount)
	api.AssertIsEqual(circuit.NumOverwrites, overwrittenCount)
}
