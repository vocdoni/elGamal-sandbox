package voteverifier

import (
	"encoding/json"
	"fmt"
	"math"
	"math/big"
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
	ptest "github.com/vocdoni/gnark-crypto-primitives/testutil"
	ztest "github.com/vocdoni/vocdoni-z-sandbox/circuits/test"
	"github.com/vocdoni/vocdoni-z-sandbox/encrypt"

	"go.vocdoni.io/dvote/util"
)

func TestVerifyVoteCircuit(t *testing.T) {
	c := qt.New(t)

	// CLIENT SIDE CIRCOM CIRCUIT

	fields := ztest.GenerateBallotFields(ztest.MaxCount, ztest.MaxValue, ztest.MinValue, ztest.ForceUniqueness > 0)
	// generate encryption key and user nonce k
	encryptionKey := ztest.GenerateEncryptionTestKey()
	encryptionKeyX, encryptionKeyY := encryptionKey.Point()
	k, err := encrypt.RandK()
	c.Assert(err, qt.IsNil)
	// encrypt the ballots
	cipherfields, plainCipherfields := ztest.CipherBallotFields(fields, ztest.NFields, encryptionKey, k)
	// generate voter account
	privKey, pubKey, address, err := ztest.GenerateECDSAaccount()
	c.Assert(err, qt.IsNil)
	// generate the commitment
	processID := util.RandomBytes(20)
	secret := util.RandomBytes(16)
	commitment, nullifier, err := ztest.MockedCommitmentAndNullifier(address.Bytes(), processID, secret)
	c.Assert(err, qt.IsNil)
	// group the circom inputs to hash
	bigCircomInputs := []*big.Int{
		big.NewInt(int64(ztest.MaxCount)),
		big.NewInt(int64(ztest.ForceUniqueness)),
		big.NewInt(int64(ztest.MaxValue)),
		big.NewInt(int64(ztest.MinValue)),
		big.NewInt(int64(math.Pow(float64(ztest.MaxValue), float64(ztest.CostExp))) * int64(ztest.MaxCount)),
		big.NewInt(int64(ztest.MaxCount)),
		big.NewInt(int64(ztest.CostExp)),
		big.NewInt(int64(ztest.CostFromWeight)),
		arbotree.BigToFF(arbotree.BN254BaseField, new(big.Int).SetBytes(address.Bytes())),
		big.NewInt(int64(ztest.Weight)),
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
	// the resulting hash should have 32 bytes so if it does'nt, fill with 0s
	blsCircomInputsHash := arbotree.BigToFF(ecc.BLS12_377.ScalarField(), circomInputsHash)
	if b := blsCircomInputsHash.Bytes(); len(b) < 32 {
		for len(b) < 32 {
			b = append(b, 0)
		}
		blsCircomInputsHash.SetBytes(b)
	}
	// sign the inputs hash with the private key
	rSign, sSign, err := ztest.SignECDSA(privKey, blsCircomInputsHash.Bytes())
	c.Assert(err, qt.IsNil)
	// init circom inputs
	circomInputs := map[string]any{
		"fields":           ztest.BigIntArrayToStringArray(fields, ztest.NFields),
		"max_count":        fmt.Sprint(ztest.MaxCount),
		"force_uniqueness": fmt.Sprint(ztest.ForceUniqueness),
		"max_value":        fmt.Sprint(ztest.MaxValue),
		"min_value":        fmt.Sprint(ztest.MinValue),
		"max_total_cost":   fmt.Sprint(int(math.Pow(float64(ztest.MaxValue), float64(ztest.CostExp))) * ztest.MaxCount),
		"min_total_cost":   fmt.Sprint(ztest.MaxCount),
		"cost_exp":         fmt.Sprint(ztest.CostExp),
		"cost_from_weight": fmt.Sprint(ztest.CostFromWeight),
		"address":          arbotree.BigToFF(arbotree.BN254BaseField, new(big.Int).SetBytes(address.Bytes())).String(),
		"weight":           fmt.Sprint(ztest.Weight),
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
	placeholders, err := ztest.Circom2GnarkPlaceholder()
	c.Assert(err, qt.IsNil)
	proof, err := ztest.Circom2GnarkProof(bCircomInputs)
	c.Assert(err, qt.IsNil)
	// transform cipherfields to gnark frontend.Variable
	emulatedBallots := [ztest.NFields][2][2]emulated.Element[sw_bn254.ScalarField]{}
	for i, c := range cipherfields {
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
	// generate a test census proof
	testCensus, err := ptest.GenerateCensusProofForTest(ptest.CensusTestConfig{
		Dir:           "../assets/census",
		ValidSiblings: 10,
		TotalSiblings: ztest.NLevels,
		KeyLen:        20,
		Hash:          arbotree.HashFunctionMiMC_BLS12_377,
		BaseFiled:     arbotree.BLS12377BaseField,
	}, [][]byte{address.Bytes()}, [][]byte{new(big.Int).SetInt64(int64(ztest.Weight)).Bytes()})
	c.Assert(err, qt.IsNil)
	// transform siblings to gnark frontend.Variable
	fSiblings := [ztest.NLevels]frontend.Variable{}
	for i, s := range testCensus.Proofs[0].Siblings {
		fSiblings[i] = frontend.Variable(s)
	}
	// hash the inputs of gnark circuit (circom inputs hash + census root)
	hFn := mimc.NewMiMC()
	hFn.Write(blsCircomInputsHash.Bytes())
	hFn.Write(testCensus.Root.Bytes())
	inputsHash := new(big.Int).SetBytes(hFn.Sum(nil))
	// compose circuit placeholders
	placeholder := VerifyVoteCircuit{
		CircomProof:            placeholders.Proof,
		CircomPublicInputsHash: placeholders.Witness,
		CircomVerificationKey:  placeholders.Vk,
	}

	// SERVER SIDE GNARK CIRCUIT

	// init inputs
	witness := VerifyVoteCircuit{
		InputsHash: inputsHash,
		// circom inputs
		MaxCount:        emulated.ValueOf[sw_bn254.ScalarField](ztest.MaxCount),
		ForceUniqueness: emulated.ValueOf[sw_bn254.ScalarField](ztest.ForceUniqueness),
		MaxValue:        emulated.ValueOf[sw_bn254.ScalarField](ztest.MaxValue),
		MinValue:        emulated.ValueOf[sw_bn254.ScalarField](ztest.MinValue),
		MaxTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](int(math.Pow(float64(ztest.MaxValue), float64(ztest.CostExp))) * ztest.MaxCount),
		MinTotalCost:    emulated.ValueOf[sw_bn254.ScalarField](ztest.MaxCount),
		CostExp:         emulated.ValueOf[sw_bn254.ScalarField](ztest.CostExp),
		CostFromWeight:  emulated.ValueOf[sw_bn254.ScalarField](ztest.CostFromWeight),
		Address:         emulated.ValueOf[sw_bn254.ScalarField](address.Big()),
		UserWeight:      emulated.ValueOf[sw_bn254.ScalarField](ztest.Weight),
		EncryptionPubKey: [2]emulated.Element[sw_bn254.ScalarField]{
			emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyX),
			emulated.ValueOf[sw_bn254.ScalarField](encryptionKeyY),
		},
		Nullifier:       emulated.ValueOf[sw_bn254.ScalarField](nullifier),
		Commitment:      emulated.ValueOf[sw_bn254.ScalarField](commitment),
		ProcessId:       emulated.ValueOf[sw_bn254.ScalarField](arbotree.BigToFF(arbotree.BN254BaseField, new(big.Int).SetBytes(processID))),
		EncryptedBallot: emulatedBallots,
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
