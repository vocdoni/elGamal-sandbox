package ballotproof

import "github.com/vocdoni/circom2gnark/parser"

// Circom2GnarkProof
func Circom2GnarkProof(witness []byte) (*parser.GnarkRecursionProof, error) {
	// create circom proof and public signals
	circomProof, pubSignals, err := CompileAndGenerateProofForTest(witness)
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
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vkey)
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
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vkey)
	if err != nil {
		return nil, err
	}
	return parser.PlaceholdersForRecursion(gnarkVKeyData, 1, true)
}
