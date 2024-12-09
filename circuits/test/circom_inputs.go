package test

import (
	"os"

	"github.com/vocdoni/circom2gnark/parser"
)

const (
	// circom assets and config
	NFields         = 8
	BallotProofWasm = "../assets/circom/circuit/ballot_proof.wasm"
	BallotProofPKey = "../assets/circom/circuit/ballot_proof_pkey.zkey"
	BallotProofVKey = "../assets/circom/circuit/ballot_proof_vkey.json"
	// process config
	NLevels         = 160
	MaxCount        = 5
	ForceUniqueness = 0
	MaxValue        = 16
	MinValue        = 0
	CostExp         = 2
	CostFromWeight  = 0
	Weight          = 10
)

// Circom2GnarkProof
func Circom2GnarkProof(witness []byte) (*parser.GnarkRecursionProof, error) {
	// create circom proof and public signals
	circomProof, pubSignals, err := CompileAndGenerateProof(witness, BallotProofWasm, BallotProofPKey)
	// load data from assets
	vKeyData, err := os.ReadFile(BallotProofVKey)
	if err != nil {
		return nil, err
	}
	// transform to gnark format
	gnarkProofData, err := parser.UnmarshalCircomProofJSON([]byte(circomProof))
	if err != nil {
		return nil, err
	}
	gnarkPubSignalsData, err := parser.UnmarshalCircomPublicSignalsJSON([]byte(pubSignals))
	if err != nil {
		return nil, err
	}
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vKeyData)
	if err != nil {
		return nil, err
	}
	proof, err := parser.ConvertCircomToGnarkRecursion(gnarkVKeyData, gnarkProofData, gnarkPubSignalsData, true)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

// Circom2GnarkPlaceholder
func Circom2GnarkPlaceholder() (*parser.GnarkRecursionPlaceholders, error) {
	// load data from assets
	vKeyData, err := os.ReadFile(BallotProofVKey)
	if err != nil {
		return nil, err
	}
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vKeyData)
	if err != nil {
		return nil, err
	}
	return parser.PlaceholdersForRecursion(gnarkVKeyData, 1, true)
}
