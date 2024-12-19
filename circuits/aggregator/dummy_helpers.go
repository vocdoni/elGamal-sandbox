package aggregator

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// EncodeProofsSelector function returns a number that its base2 representation
// contains the first nValidProofs bits set to one. It allows to encode the
// number of valid proofs as selector to switch between main circuit vk and the
// dummy one.
func EncodeProofsSelector(nValidProofs int) *big.Int {
	// no valid number if nValidProofs <= 0
	if nValidProofs <= 0 {
		return big.NewInt(0)
	}
	// (1 << nValidProofs) - 1 gives a binary number with nValidProofs ones
	// compute (1 << n) - 1
	maxNum := big.NewInt(1)
	// left shift by 'n'
	maxNum.Lsh(maxNum, uint(nValidProofs))
	// subtract 1 to get all n set to 1
	return maxNum.Sub(maxNum, big.NewInt(1))
}

// FillWithDummyFixed function fills the placeholder and the assigments
// provided with a dummy circuit stuff and proofs compiled for the main
// constraint.ConstraintSystem provided. It starts to fill from the index
// provided and fixes the dummy verification key. Returns an error if
// something fails.
func FillWithDummyFixed(placeholder, assigments *AggregatorCircuit, main constraint.ConstraintSystem, fromIdx int) error {
	// compile the dummy circuit for the main
	dummyCCS, pubWitness, proof, vk, err := compileAndVerifyCircuit(
		DummyPlaceholder(main), DummyAssigment(),
		ecc.BW6_761.ScalarField(), ecc.BLS12_377.ScalarField())
	if err != nil {
		return err
	}
	// set fixed dummy vk in the placeholders
	placeholder.VerificationKeys[0], err = stdgroth16.ValueOfVerifyingKeyFixed[sw_bls12377.G1Affine, sw_bls12377.G2Affine, sw_bls12377.GT](vk)
	if err != nil {
		return fmt.Errorf("fix dummy vk error: %w", err)
	}
	// parse dummy proof and witness
	dummyProof, err := stdgroth16.ValueOfProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](proof)
	if err != nil {
		return fmt.Errorf("dummy proof value error: %w", err)
	}
	dummyWitness, err := stdgroth16.ValueOfWitness[sw_bls12377.ScalarField](pubWitness)
	if err != nil {
		return fmt.Errorf("dummy witness value error: %w", err)
	}
	// set some dummy values in others assigments variables
	dummyValue := frontend.Variable(0)
	var dummyEncryptedBallots [MaxFields][2][2]frontend.Variable
	for i := 0; i < MaxFields; i++ {
		dummyEncryptedBallots[i] = [2][2]frontend.Variable{
			{dummyValue, dummyValue}, {dummyValue, dummyValue},
		}
	}
	// fill placeholders and assigments dummy values
	for i := range assigments.VerifyProofs {
		if i >= fromIdx {
			placeholder.VerifyProofs[i] = stdgroth16.PlaceholderProof[sw_bls12377.G1Affine, sw_bls12377.G2Affine](dummyCCS)
			placeholder.VerifyPublicInputs[i] = stdgroth16.PlaceholderWitness[sw_bls12377.ScalarField](dummyCCS)

			assigments.Nullifiers[i] = dummyValue
			assigments.Commitments[i] = dummyValue
			assigments.Addresses[i] = dummyValue
			assigments.EncryptedBallots[i] = dummyEncryptedBallots
			assigments.VerifyProofs[i] = dummyProof
			assigments.VerifyPublicInputs[i] = dummyWitness
		}
	}
	return nil
}

func compileAndVerifyCircuit(placeholder, assigment frontend.Circuit, outer *big.Int, field *big.Int) (constraint.ConstraintSystem, witness.Witness, groth16.Proof, groth16.VerifyingKey, error) {
	ccs, err := frontend.Compile(field, r1cs.NewBuilder, placeholder)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("compile error: %w", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("setup error: %w", err)
	}
	fullWitness, err := frontend.NewWitness(assigment, field)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("full witness error: %w", err)
	}
	proof, err := groth16.Prove(ccs, pk, fullWitness, stdgroth16.GetNativeProverOptions(outer, field))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("proof error: %w", err)
	}
	publicWitness, err := fullWitness.Public()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("pub witness error: %w", err)
	}
	if err = groth16.Verify(proof, vk, publicWitness, stdgroth16.GetNativeVerifierOptions(outer, field)); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("verify error: %w", err)
	}
	return ccs, publicWitness, proof, vk, nil
}
