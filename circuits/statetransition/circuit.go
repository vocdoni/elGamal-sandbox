package statetransition

import (
	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/gnark-crypto-primitives/elgamal"
	"github.com/vocdoni/gnark-crypto-primitives/hash/bn254/poseidon"
	"github.com/vocdoni/gnark-crypto-primitives/tree/arbo"
)

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

	ProcessID     MerkleProof
	CensusRoot    MerkleProof
	BallotMode    MerkleProof
	EncryptionKey MerkleProof
	ResultsAdd    MerkleTransition
	ResultsSub    MerkleTransition
	Ballot        [VoteBatchSize]MerkleTransition
	Commitment    [VoteBatchSize]MerkleTransition

	EncryptedBallots [VoteBatchSize]EncryptedBallot
}

type EncryptedBallot struct {
	A   elgamal.Ciphertext
	B   elgamal.Ciphertext
	Sum elgamal.Ciphertext
}

// Define declares the circuit's constraints
func (circuit Circuit) Define(api frontend.API) error {
	circuit.verifyAggregatedZKProof(api)
	circuit.verifyMerkleProofs(api, poseidon.Hash)
	circuit.verifyMerkleTransitions(api)
	circuit.verifyBallots(api)
	return nil
}

func (circuit Circuit) verifyAggregatedZKProof(api frontend.API) {
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
		for i, p := range []MerkleProof{
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

func (circuit Circuit) verifyMerkleProofs(api frontend.API, hFn arbo.Hash) {
	api.Println("verify ProcessID, CensusRoot, BallotMode and EncryptionKey belong to RootHashBefore")
	circuit.ProcessID.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.CensusRoot.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.BallotMode.VerifyProof(api, hFn, circuit.RootHashBefore)
	circuit.EncryptionKey.VerifyProof(api, hFn, circuit.RootHashBefore)
}

func (circuit Circuit) verifyMerkleTransitions(api frontend.API) {
	// verify chain of tree transitions, order here is fundamental.
	api.Println("tree transition starts with RootHashBefore:", prettyHex(circuit.RootHashBefore))
	root := circuit.RootHashBefore
	for i := range circuit.Ballot {
		root = circuit.Ballot[i].Verify(api, root)
	}
	for i := range circuit.Commitment {
		root = circuit.Commitment[i].Verify(api, root)
	}
	root = circuit.ResultsAdd.Verify(api, root)
	root = circuit.ResultsSub.Verify(api, root)
	api.Println("and final root is", prettyHex(root), "should be equal to RootHashAfter", prettyHex(circuit.RootHashAfter))
	api.AssertIsEqual(root, circuit.RootHashAfter)
}

// verifyBallots counts the ballots using homomorphic encrpytion
func (circuit Circuit) verifyBallots(api frontend.API) error {
	c := circuit.EncryptedBallots[0]
	// calculate and check sum
	sum := &elgamal.Ciphertext{}
	sum.Add(api, &c.A, &c.B)
	sum.AssertIsEqual(api, &c.Sum)
	return nil
	// var ballotSum, overwrittenSum, ballotCount, overwrittenCount frontend.Variable = 0, 0, 0, 0

	// for _, b := range circuit.Ballot {
	// 	ballotSum = api.Add(ballotSum, api.Select(api.Or(isUpdate(api, b), isInsert(api, b)),
	// 		b.NewValue, 0))
	// 	overwrittenSum = api.Add(overwrittenSum, api.Select(isUpdate(api, b),
	// 		b.OldValue, 0))
	// 	ballotCount = api.Add(ballotCount, api.Select(api.Or(isUpdate(api, b), isInsert(api, b)),
	// 		1, 0))
	// 	overwrittenCount = api.Add(overwrittenCount, api.Select(isUpdate(api, b),
	// 		1, 0))
	// }

	// api.AssertIsEqual(
	// 	api.Add(circuit.ResultsAdd.OldValue, ballotSum),
	// 	circuit.ResultsAdd.NewValue)
	// api.AssertIsEqual(
	// 	api.Add(circuit.ResultsSub.OldValue, overwrittenSum),
	// 	circuit.ResultsSub.NewValue)
	// api.AssertIsEqual(circuit.NumNewVotes, ballotCount)
	// api.AssertIsEqual(circuit.NumOverwrites, overwrittenCount)
}

// verifyMockBallots counts the ballots using a simple api.Add
//
// (not intended for production, just for testing purposes)
func (circuit Circuit) verifyMockBallots(api frontend.API) {
	var ballotSum, overwrittenSum, ballotCount, overwrittenCount frontend.Variable = 0, 0, 0, 0

	for _, b := range circuit.Ballot {
		ballotSum = api.Add(ballotSum, api.Select(api.Or(isUpdate(api, b), isInsert(api, b)),
			b.NewValue, 0))
		overwrittenSum = api.Add(overwrittenSum, api.Select(isUpdate(api, b),
			b.OldValue, 0))
		ballotCount = api.Add(ballotCount, api.Select(api.Or(isUpdate(api, b), isInsert(api, b)),
			1, 0))
		overwrittenCount = api.Add(overwrittenCount, api.Select(isUpdate(api, b),
			1, 0))
	}

	api.AssertIsEqual(
		api.Add(circuit.ResultsAdd.OldValue, ballotSum),
		circuit.ResultsAdd.NewValue)
	api.AssertIsEqual(
		api.Add(circuit.ResultsSub.OldValue, overwrittenSum),
		circuit.ResultsSub.NewValue)
	api.AssertIsEqual(circuit.NumNewVotes, ballotCount)
	api.AssertIsEqual(circuit.NumOverwrites, overwrittenCount)
}

// isUpdate returns true when mp.Fnc0 == 0 && mp.Fnc1 == 1
func isUpdate(api frontend.API, mp MerkleTransition) frontend.Variable {
	fnc0IsZero := api.IsZero(mp.Fnc0)
	fnc1IsOne := api.Sub(1, api.IsZero(mp.Fnc1))
	return api.And(fnc0IsZero, fnc1IsOne)
}

// isInsert returns true when mp.Fnc0 == 1 && mp.Fnc1 == 0
func isInsert(api frontend.API, mp MerkleTransition) frontend.Variable {
	fnc0IsOne := api.Sub(1, api.IsZero(mp.Fnc0))
	fnc1IsZero := api.IsZero(mp.Fnc1)
	return api.And(fnc1IsZero, fnc0IsOne)
}
