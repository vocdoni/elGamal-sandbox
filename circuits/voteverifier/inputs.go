package voteverifier

import (
	"crypto/ecdsa"
	"math"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/vocdoni/arbo"
	primitivestest "github.com/vocdoni/gnark-crypto-primitives/testutil"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/ballotproof"
	"go.vocdoni.io/dvote/util"
)

// VoteVerifierTestResults struct includes relevant data after VerifyVoteCircuit
// inputs generation
type VoteVerifierTestResults struct {
	EncryptionPubKey [2]*big.Int
	ProcessID        []byte
	CensusRoot       *big.Int
	Nullifiers       []*big.Int
	Commitments      []*big.Int
	EncryptedBallots [][ballotproof.NFields][2][2]*big.Int
}

// VoterTestData struct includes the information required to generate the test
// inputs for the VerifyVoteCircuit.
type VoterTestData struct {
	PrivKey *ecdsa.PrivateKey
	PubKey  ecdsa.PublicKey
	Address common.Address
}

// GenInputsForTest returns the VoteVerifierTestResults, the placeholder and
// the assigments for a VerifyVoteCircuit including the provided voters. If
// processId is nil, it will be randomly generated. If something fails it
// returns an error.
func GenInputsForTest(votersData []VoterTestData, processId []byte) (*VoteVerifierTestResults, VerifyVoteCircuit, []VerifyVoteCircuit, error) {
	circomPlaceholder, err := ballotproof.Circom2GnarkPlaceholder()
	if err != nil {
		return nil, VerifyVoteCircuit{}, nil, err
	}
	bAddresses, bWeights := [][]byte{}, [][]byte{}
	for _, voter := range votersData {
		bAddresses = append(bAddresses, voter.Address.Bytes())
		bWeights = append(bWeights, new(big.Int).SetInt64(int64(ballotproof.Weight)).Bytes())
	}
	// generate a test census
	testCensus, err := primitivestest.GenerateCensusProofForTest(primitivestest.CensusTestConfig{
		Dir:           "../assets/census",
		ValidSiblings: 10,
		TotalSiblings: ballotproof.NLevels,
		KeyLen:        20,
		Hash:          arbo.HashFunctionMiMC_BLS12_377,
		BaseFiled:     arbo.BLS12377BaseField,
	}, bAddresses, bWeights)
	if err != nil {
		return nil, VerifyVoteCircuit{}, nil, err
	}
	// common data
	if processId != nil {
		processId = util.RandomBytes(20)
	}
	encryptionKey := ballotproof.GenEncryptionKeyForTest()
	encryptionKeyX, encryptionKeyY := encryptionKey.Point()
	// circuits assigments, voters data and proofs
	var assigments []VerifyVoteCircuit
	nullifiers, commitments := []*big.Int{}, []*big.Int{}
	encryptedBallots := [][ballotproof.NFields][2][2]*big.Int{}
	for i, voter := range votersData {
		voterProof, err := ballotproof.MockVoterForTest(voter.Address.Bytes(), processId, encryptionKey)
		if err != nil {
			return nil, VerifyVoteCircuit{}, nil, err
		}
		nullifiers = append(nullifiers, voterProof.Nullifier)
		commitments = append(commitments, voterProof.Commitment)
		encryptedBallots = append(encryptedBallots, voterProof.EncryptedFields)
		// transform the inputs hash to the field of the curve used by the circuit,
		// if it is not done, the circuit will transform it during witness
		// calculation and the hash will be different
		// the resulting hash should have 32 bytes so if it does'nt, fill with 0s
		blsCircomInputsHash := arbo.BigToFF(ecc.BLS12_377.ScalarField(), voterProof.InputsHash)
		if b := blsCircomInputsHash.Bytes(); len(b) < 32 {
			for len(b) < 32 {
				b = append(b, 0)
			}
			blsCircomInputsHash.SetBytes(b)
		}
		// sign the inputs hash with the private key
		rSign, sSign, err := ballotproof.SignECDSAForTest(voter.PrivKey, blsCircomInputsHash.Bytes())
		if err != nil {
			return nil, VerifyVoteCircuit{}, nil, err
		}
		// transform encryptedBallots to gnark frontend.Variable
		emulatedBallots := [ballotproof.NFields][2][2]emulated.Element[sw_bn254.ScalarField]{}
		for i, c := range voterProof.EncryptedFields {
			emulatedBallots[i] = [2][2]emulated.Element[sw_bn254.ScalarField]{
				{
					emulated.ValueOf[sw_bn254.ScalarField](c[0][0]),
					emulated.ValueOf[sw_bn254.ScalarField](c[0][1]),
				},
				{
					emulated.ValueOf[sw_bn254.ScalarField](c[1][0]),
					emulated.ValueOf[sw_bn254.ScalarField](c[1][1]),
				},
			}
		}
		// transform siblings to gnark frontend.Variable
		fSiblings := [ballotproof.NLevels]frontend.Variable{}
		for i, s := range testCensus.Proofs[i].Siblings {
			fSiblings[i] = frontend.Variable(s)
		}
		// hash the inputs of gnark circuit (circom inputs hash + census root)
		hFn := mimc.NewMiMC()
		hFn.Write(blsCircomInputsHash.Bytes())
		hFn.Write(testCensus.Root.Bytes())
		inputsHash := new(big.Int).SetBytes(hFn.Sum(nil))
		// compose circuit placeholders
		assigments = append(assigments, VerifyVoteCircuit{
			InputsHash: inputsHash,
			// circom inputs
			MaxCount:        emulated.ValueOf[sw_bn254.ScalarField](ballotproof.MaxCount),
			ForceUniqueness: emulated.ValueOf[sw_bn254.ScalarField](ballotproof.ForceUniqueness),
			MaxValue:        emulated.ValueOf[sw_bn254.ScalarField](ballotproof.MaxValue),
			MinValue:        emulated.ValueOf[sw_bn254.ScalarField](ballotproof.MinValue),
			MaxTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](int(math.Pow(float64(ballotproof.MaxValue), float64(ballotproof.CostExp))) * ballotproof.MaxCount),
			MinTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](ballotproof.MaxCount),
			CostExp:         emulated.ValueOf[sw_bn254.ScalarField](ballotproof.CostExp),
			CostFromWeight:  emulated.ValueOf[sw_bn254.ScalarField](ballotproof.CostFromWeight),
			Address:         emulated.ValueOf[sw_bn254.ScalarField](voterProof.Address),
			UserWeight:      emulated.ValueOf[sw_bn254.ScalarField](ballotproof.Weight),
			EncryptionPubKey: [2]emulated.Element[sw_bn254.ScalarField]{
				emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyX),
				emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyY),
			},
			Nullifier:       emulated.ValueOf[sw_bn254.ScalarField](voterProof.Nullifier),
			Commitment:      emulated.ValueOf[sw_bn254.ScalarField](voterProof.Commitment),
			ProcessId:       emulated.ValueOf[sw_bn254.ScalarField](voterProof.ProcessID),
			EncryptedBallot: emulatedBallots,
			// census proof
			CensusRoot:     testCensus.Root,
			CensusSiblings: fSiblings,
			// signature
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](blsCircomInputsHash),
			PublicKey: gnarkecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](voter.PubKey.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](voter.PubKey.Y),
			},
			Signature: gnarkecdsa.Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](rSign),
				S: emulated.ValueOf[emulated.Secp256k1Fr](sSign),
			},
			// circom proof
			CircomProof:            voterProof.Proof.Proof,
			CircomPublicInputsHash: voterProof.Proof.PublicInputs,
		})
	}

	return &VoteVerifierTestResults{
			EncryptionPubKey: [2]*big.Int{encryptionKeyX, encryptionKeyY},
			ProcessID:        processId,
			CensusRoot:       testCensus.Root,
			Nullifiers:       nullifiers,
			Commitments:      commitments,
			EncryptedBallots: encryptedBallots,
		}, VerifyVoteCircuit{
			CircomVerificationKey:  circomPlaceholder.Vk,
			CircomProof:            circomPlaceholder.Proof,
			CircomPublicInputsHash: circomPlaceholder.Witness,
		}, assigments, nil
}
