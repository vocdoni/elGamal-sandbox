// aggregator package contains the Gnark circuit defiinition that aggregates
// some votes and proves the validity of the aggregation. The circuit checks
// every single verification proof generating a single proof for the whole
// aggregation. Every voter proof should use the same values for the following
// inputs:
//   - MaxCount
//   - ForceUniqueness
//   - MaxValue
//   - MinValue
//   - MaxTotalCost
//   - MinTotalCost
//   - CostExp
//   - CostFromWeight
//   - EncryptionPubKey
//   - ProcessId
//   - CensusRoot
//
// All these values are common for the same process.
//
// The circuit also checks the other inputs that are unique for each voter:
//   - Nullifier
//   - Commitment
//   - Address
//   - EncryptedBallots
//   - VerifyProof (generated with the VerifyVoteCircuit)
package aggregator

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/commitments/pedersen"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/recursion/groth16"
)

const MaxVotes = 10

type AggregatorCircuit struct {
	InputsHash    frontend.Variable `gnark:",public"`
	ValidVotes    frontend.Variable `gnark:",public"`
	ValidVotesBin frontend.Variable `gnark:",public"`
	// The following variables are priv-public inputs, so should be hashed and
	// compared with the InputsHash. All the variables should be hashed in the
	// same order as they are defined here.
	MaxCount         frontend.Variable                    // Part of InputsHash
	ForceUniqueness  frontend.Variable                    // Part of InputsHash
	MaxValue         frontend.Variable                    // Part of InputsHash
	MinValue         frontend.Variable                    // Part of InputsHash
	MaxTotalCost     frontend.Variable                    // Part of InputsHash
	MinTotalCost     frontend.Variable                    // Part of InputsHash
	CostExp          frontend.Variable                    // Part of InputsHash
	CostFromWeight   frontend.Variable                    // Part of InputsHash
	EncryptionPubKey [2]frontend.Variable                 // Part of InputsHash
	ProcessId        frontend.Variable                    // Part of InputsHash
	CensusRoot       frontend.Variable                    // Part of InputsHash
	Nullifiers       [MaxVotes]frontend.Variable          // Part of InputsHash
	Commitments      [MaxVotes]frontend.Variable          // Part of InputsHash
	Addresses        [MaxVotes]frontend.Variable          // Part of InputsHash
	EncryptedBallots [MaxVotes][8][2][2]frontend.Variable // Part of InputsHash
	// VerifyCircuit proofs
	VerifyProofs          [MaxVotes]groth16.Proof[sw_bls12377.G1Affine, sw_bls12377.G2Affine]
	VerifyPublicInputs    [MaxVotes]groth16.Witness[sw_bls12377.ScalarField]
	VerifyVerificationKey groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
	DummyVerificationKey  groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT] `gnark:"-"`
}

func (c *AggregatorCircuit) checkInputs(api frontend.API) error {
	// group all the inputs to hash them
	inputs := []frontend.Variable{
		c.MaxCount, c.ForceUniqueness, c.MaxValue, c.MinValue, c.MaxTotalCost,
		c.MinTotalCost, c.CostExp, c.CostFromWeight, c.EncryptionPubKey[0],
		c.EncryptionPubKey[1], c.ProcessId, c.CensusRoot,
	}
	inputs = append(inputs, c.Nullifiers[:]...)
	inputs = append(inputs, c.Commitments[:]...)
	inputs = append(inputs, c.Addresses[:]...)
	// include flattened EncryptedBallots
	for _, voterBallots := range c.EncryptedBallots {
		for _, ballot := range voterBallots {
			inputs = append(inputs, ballot[0][0], ballot[0][1], ballot[1][0], ballot[1][1])
		}
	}
	// hash the inputs
	hFn, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hFn.Write(inputs...)
	// compare the hash with the provided InputsHash
	api.AssertIsEqual(c.InputsHash, hFn.Sum())
	return nil
}

func (c *AggregatorCircuit) SwitchVerificationKey(api frontend.API, selector frontend.Variable) (groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT], error) {
	nilVk := groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{}
	if len(c.VerifyVerificationKey.G1.K) != len(c.DummyVerificationKey.G1.K) {
		api.Println(len(c.VerifyVerificationKey.G1.K), len(c.DummyVerificationKey.G1.K))
		return nilVk, fmt.Errorf("g1 k len missmatch")
	}
	if len(c.VerifyVerificationKey.CommitmentKeys) != len(c.DummyVerificationKey.CommitmentKeys) {
		api.Println(len(c.VerifyVerificationKey.CommitmentKeys), len(c.DummyVerificationKey.CommitmentKeys))
		return nilVk, fmt.Errorf("commitmentKeys len missmatch")
	}
	// select between G1's
	k := []sw_bls12377.G1Affine{}
	for i, vkk := range c.VerifyVerificationKey.G1.K {
		k = append(k, *vkk.Select(api, selector, vkk, c.DummyVerificationKey.G1.K[i]))
	}
	// select between G2's
	gammaNeg := sw_bls12377.G2Affine{
		P: *c.VerifyVerificationKey.G2.GammaNeg.P.Select(api, selector, c.VerifyVerificationKey.G2.GammaNeg.P, c.DummyVerificationKey.G2.GammaNeg.P),
	}
	deltaNeg := sw_bls12377.G2Affine{
		P: *c.VerifyVerificationKey.G2.DeltaNeg.P.Select(api, selector, c.VerifyVerificationKey.G2.DeltaNeg.P, c.DummyVerificationKey.G2.DeltaNeg.P),
	}
	// select between CommitmentKeys'
	commitmentKeys := []pedersen.VerifyingKey[sw_bls12377.G2Affine]{}
	for i, vkck := range c.VerifyVerificationKey.CommitmentKeys {
		commitmentKeys = append(commitmentKeys, pedersen.VerifyingKey[sw_bls12377.G2Affine]{
			G: sw_bls12377.G2Affine{
				P: *vkck.G.P.Select(api, selector, vkck.G.P, c.DummyVerificationKey.CommitmentKeys[i].G.P),
			},
			GSigmaNeg: sw_bls12377.G2Affine{
				P: *vkck.G.P.Select(api, selector, vkck.GSigmaNeg.P, c.DummyVerificationKey.CommitmentKeys[i].GSigmaNeg.P),
			},
		})
	}
	// return the built vk selecting between E's
	return groth16.VerifyingKey[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT]{
		E:  *c.VerifyVerificationKey.E.Select(api, selector, c.VerifyVerificationKey.E, c.DummyVerificationKey.E),
		G1: struct{ K []sw_bls12377.G1Affine }{k},
		G2: struct {
			GammaNeg sw_bls12377.G2Affine
			DeltaNeg sw_bls12377.G2Affine
		}{
			GammaNeg: gammaNeg,
			DeltaNeg: deltaNeg,
		},
		CommitmentKeys: commitmentKeys,
	}, nil
}

func (c *AggregatorCircuit) Define(api frontend.API) error {
	// check the inputs of the circuit
	if err := c.checkInputs(api); err != nil {
		return err
	}
	// initialize the verifier
	verifier, err := groth16.NewVerifier[sw_bls12377.ScalarField, sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](api)
	if err != nil {
		return err
	}
	// verify each proof with the provided public inputs and the fixed
	// verification key
	totalValidVotes := frontend.Variable(0)
	validProofs := bits.ToBinary(api, c.ValidVotesBin)
	for i := 0; i < len(c.VerifyProofs); i++ {
		vk, err := c.SwitchVerificationKey(api, validProofs[i])
		if err != nil {
			return err
		}
		numErr := 1
		if err := verifier.AssertProof(vk, c.VerifyProofs[i], c.VerifyPublicInputs[i]); err != nil {
			numErr = 0
		}
		totalValidVotes = api.Add(totalValidVotes, api.Mul(numErr, validProofs[i]))
	}
	api.AssertIsEqual(totalValidVotes, c.ValidVotes)
	return nil
}
