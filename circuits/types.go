package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/recursion/groth16"
)

// ProcessMetadata contains the metadata of a process, including the maximum
// number of of fields for a ballot, if every ballot field must be unique, the
// maximum and minimum value for each field, the maximum and minimum total value
// for all fields, the cost exponent, and a flag to define if the cost comes
// from the weight or from MaxTotalCost attribute.
type ProcessMetadata struct {
	MaxCount        frontend.Variable
	ForceUniqueness frontend.Variable
	MaxValue        frontend.Variable
	MinValue        frontend.Variable
	MaxTotalCost    frontend.Variable
	MinTotalCost    frontend.Variable
	CostExp         frontend.Variable
	CostFromWeight  frontend.Variable
}

// CircomProof contains the proof generated by a Circom circuit with snarkjs and
// the required public inputs to verify the proof to verify the proof with
// gnark.
type CircomProof struct {
	Proof        groth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	Vk           groth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
	PublicInputs groth16.Witness[sw_bn254.ScalarField]
}

// CensusProof contains the proof that a user is part of a census merkle tree.
// It includes the root of the merkle tree, the key of the user, the value of
// the user leaf, and the siblings of the user leaf. The number of siblings is
// fixed to 160 but the circuit will only use the necessary ones.
type CensusProof struct {
	Root     frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable
	Siblings [160]frontend.Variable
}
