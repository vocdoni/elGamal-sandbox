package voteverifier

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	gecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/iden3/go-iden3-crypto/mimc7"
	arbotree "github.com/vocdoni/arbo"
	"github.com/vocdoni/circom2gnark/parser"
	ptestutil "github.com/vocdoni/gnark-crypto-primitives/testutil"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/testutil"
	"github.com/vocdoni/vocdoni-z-sandbox/encrypt"

	"go.vocdoni.io/dvote/util"
)

const (
	n_fields = 8
	n_levels = 160
)

var (
	ballotProofWasm = "../assets/circom/circuit/ballot_proof.wasm"
	ballotProofPKey = "../assets/circom/circuit/ballot_proof_pkey.zkey"
	ballotProofVKey = "../assets/circom/circuit/ballot_proof_vkey.json"

	maxCount        = 5
	forceUniqueness = 0
	maxValue        = 16
	minValue        = 0
	costExp         = 2
	costFromWeight  = 0
	weight          = 10
	fields          = testutil.GenerateBallotFields(maxCount, maxValue, minValue, forceUniqueness > 0)
)

func TestVerifyVoteCircuit(t *testing.T) {
	c := qt.New(t)

	// CLIENT SIDE CIRCOM CIRCUIT

	// generate encryption key and user nonce k
	encryptionKey := testutil.GenerateEncryptionTestKey()
	encryptionKeyX, encryptionKeyY := encryptionKey.Point()
	k, err := encrypt.RandK()
	c.Assert(err, qt.IsNil)
	// encrypt the ballots
	cipherfields, plainCipherfields := testutil.CipherBallotFields(fields, n_fields, encryptionKey, k)
	// generate voter account
	privKey, pubKey, address, err := testutil.GenerateECDSAaccount()
	c.Assert(err, qt.IsNil)
	// generate the commitment
	processID := util.RandomBytes(20)
	secret := util.RandomBytes(16)
	commitment, nullifier, err := testutil.MockedCommitmentAndNullifier(address.Bytes(), processID, secret)
	c.Assert(err, qt.IsNil)
	// group the circom inputs to hash
	bigCircomInputs := []*big.Int{
		big.NewInt(int64(maxCount)),
		big.NewInt(int64(forceUniqueness)),
		big.NewInt(int64(maxValue)),
		big.NewInt(int64(minValue)),
		big.NewInt(int64(math.Pow(float64(maxValue), float64(costExp))) * int64(maxCount)),
		big.NewInt(int64(maxCount)),
		big.NewInt(int64(costExp)),
		big.NewInt(int64(costFromWeight)),
		arbotree.BigToFF(arbotree.BN254BaseField, new(big.Int).SetBytes(address.Bytes())),
		big.NewInt(int64(weight)),
		arbotree.BigToFF(arbotree.BN254BaseField, new(big.Int).SetBytes(processID)),
		encryptionKeyX,
		encryptionKeyY,
		nullifier,
		commitment,
	}
	bigCircomInputs = append(bigCircomInputs, plainCipherfields...)
	circomInputsHash, err := mimc7.Hash(bigCircomInputs, nil)
	c.Assert(err, qt.IsNil)
	// transform the inputs hash to the field of the curve used by the circuit,
	// if it is not done, the circuit will transform it during witness
	// calculation and the hash will be different
	blsCircomInputsHash := arbotree.BigToFF(ecc.BLS12_377.ScalarField(), circomInputsHash)
	// sign the inputs hash with the private key
	rSign, sSign, err := testutil.SignECDSA(privKey, blsCircomInputsHash.Bytes())
	// init circom inputs
	circomInputs := map[string]any{
		"fields":           testutil.BigIntArrayToStringArray(fields, n_fields),
		"max_count":        fmt.Sprint(maxCount),
		"force_uniqueness": fmt.Sprint(forceUniqueness),
		"max_value":        fmt.Sprint(maxValue),
		"min_value":        fmt.Sprint(minValue),
		"max_total_cost":   fmt.Sprint(int(math.Pow(float64(maxValue), float64(costExp))) * maxCount), // (maxValue-1)^costExp * maxCount
		"min_total_cost":   fmt.Sprint(maxCount),
		"cost_exp":         fmt.Sprint(costExp),
		"cost_from_weight": fmt.Sprint(costFromWeight),
		"address":          arbotree.BigToFF(arbotree.BN254BaseField, new(big.Int).SetBytes(address.Bytes())).String(),
		"weight":           fmt.Sprint(weight),
		"process_id":       arbotree.BigToFF(arbotree.BN254BaseField, new(big.Int).SetBytes(processID)).String(),
		"pk":               []string{encryptionKeyX.String(), encryptionKeyY.String()},
		"k":                k.String(),
		"cipherfields":     cipherfields,
		"nullifier":        nullifier.String(),
		"commitment":       commitment.String(),
		"secret":           arbotree.BigToFF(arbotree.BN254BaseField, new(big.Int).SetBytes(secret)).String(),
		"inputs_hash":      circomInputsHash.String(),
	}
	bCircomInputs, err := json.Marshal(circomInputs)
	c.Assert(err, qt.IsNil)
	// create the proof
	circomProof, pubSignals, err := testutil.CompileAndGenerateProof(bCircomInputs, ballotProofWasm, ballotProofPKey)
	c.Assert(err, qt.IsNil)
	// transform cipherfields to gnark frontend.Variable
	fBallots := [n_fields][2][2]emulated.Element[sw_bn254.ScalarField]{}
	for i, c := range cipherfields {
		fBallots[i] = [2][2]emulated.Element[sw_bn254.ScalarField]{
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
	// generate a test census proof
	testCensus, err := ptestutil.GenerateCensusProofForTest(ptestutil.CensusTestConfig{
		Dir:           "../assets/census",
		ValidSiblings: 10,
		TotalSiblings: n_levels,
		KeyLen:        20,
		Hash:          arbotree.HashFunctionMiMC_BLS12_377,
		BaseFiled:     arbotree.BLS12377BaseField,
	}, address.Bytes(), new(big.Int).SetInt64(int64(weight)).Bytes())
	c.Assert(err, qt.IsNil)
	// transform siblings to gnark frontend.Variable
	fSiblings := [n_levels]frontend.Variable{}
	for i, s := range testCensus.Siblings {
		fSiblings[i] = frontend.Variable(s)
	}
	// hash the inputs of gnark circuit (circom inputs hash + census root)
	hFn := mimc.NewMiMC()
	hFn.Write(blsCircomInputsHash.Bytes())
	hFn.Write(testCensus.Root.Bytes())
	inputsHash := new(big.Int).SetBytes(hFn.Sum(nil))
	// parse input files
	proof, placeHolders, _, err := parseCircomInputs(ballotProofVKey, circomProof, pubSignals)
	c.Assert(err, qt.IsNil)
	placeholder := VerifyVoteCircuit{
		CircomProof:            placeHolders.Proof,
		CircomPublicInputsHash: placeHolders.Witness,
		CircomVerificationKey:  placeHolders.Vk,
	}

	// SERVER SIDE GNARK CIRCUIT

	// init inputs
	witness := VerifyVoteCircuit{
		InputsHash: inputsHash,
		// circom inputs
		MaxCount:        emulated.ValueOf[sw_bn254.ScalarField](maxCount),
		ForceUniqueness: emulated.ValueOf[sw_bn254.ScalarField](forceUniqueness),
		MaxValue:        emulated.ValueOf[sw_bn254.ScalarField](maxValue),
		MinValue:        emulated.ValueOf[sw_bn254.ScalarField](minValue),
		MaxTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](int(math.Pow(float64(maxValue), float64(costExp))) * maxCount),
		MinTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](maxCount),
		CostExp:         emulated.ValueOf[sw_bn254.ScalarField](costExp),
		CostFromWeight:  emulated.ValueOf[sw_bn254.ScalarField](costFromWeight),
		Address:         emulated.ValueOf[sw_bn254.ScalarField](address.Big()),
		UserWeight:      emulated.ValueOf[sw_bn254.ScalarField](weight),
		EncryptionPubKey: [2]emulated.Element[sw_bn254.ScalarField]{
			emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyX),
			emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyY),
		},
		Nullifier:       emulated.ValueOf[sw_bn254.ScalarField](nullifier),
		Commitment:      emulated.ValueOf[sw_bn254.ScalarField](commitment),
		ProcessId:       emulated.ValueOf[sw_bn254.ScalarField](arbotree.BigToFF(arbotree.BN254BaseField, new(big.Int).SetBytes(processID))),
		EncryptedBallot: fBallots,
		// census proof
		CensusRoot:     testCensus.Root,
		CensusSiblings: fSiblings,
		// signature
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](blsCircomInputsHash),
		PublicKey: gecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pubKey.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pubKey.Y),
		},
		Signature: gecdsa.Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](rSign),
			S: emulated.ValueOf[emulated.Secp256k1Fr](sSign),
		},
		// circom proof
		CircomProof:            proof.Proof,
		CircomPublicInputsHash: proof.PublicInputs,
	}
	// generate proof
	assert := test.NewAssert(t)
	now := time.Now()
	assert.SolvingSucceeded(&placeholder, &witness,
		test.WithCurves(ecc.BLS12_377),
		test.WithBackends(backend.GROTH16))
	fmt.Println("proving tooks", time.Since(now))
}

func parseCircomInputs(vKeyFile string, rawProof, rawPubSignals string) (*parser.GnarkRecursionProof, *parser.GnarkRecursionPlaceholders, *big.Int, error) {
	// load data from assets
	vKeyData, err := os.ReadFile(vKeyFile)
	if err != nil {
		return nil, nil, nil, err
	}
	// transform to gnark format
	gnarkProofData, err := parser.UnmarshalCircomProofJSON([]byte(rawProof))
	if err != nil {
		return nil, nil, nil, err
	}
	gnarkPubSignalsData, err := parser.UnmarshalCircomPublicSignalsJSON([]byte(rawPubSignals))
	if err != nil {
		return nil, nil, nil, err
	}
	gnarkVKeyData, err := parser.UnmarshalCircomVerificationKeyJSON(vKeyData)
	if err != nil {
		return nil, nil, nil, err
	}
	proof, placeHolders, err := parser.ConvertCircomToGnarkRecursion(gnarkProofData, gnarkVKeyData, gnarkPubSignalsData, true)
	if err != nil {
		return nil, nil, nil, err
	}
	// decode pub input to get the hash to sign
	inputsHash, ok := new(big.Int).SetString(gnarkPubSignalsData[0], 10)
	if !ok {
		return nil, nil, nil, fmt.Errorf("failed to decode inputs hash")
	}
	return proof, placeHolders, inputsHash, nil
}
