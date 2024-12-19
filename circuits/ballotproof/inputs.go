package ballotproof

import (
	"crypto/ecdsa"
	"crypto/rand"
	_ "embed"
	"encoding/json"
	"fmt"
	"math"
	"math/big"

	gecdsa "github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-rapidsnark/prover"
	"github.com/iden3/go-rapidsnark/witness"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/circom2gnark/parser"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	bjj "github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/bjj_gnark"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
)

//go:embed ballot_proof.wasm
var circuit []byte

//go:embed ballot_proof_pkey.zkey
var pkey []byte

//go:embed ballot_proof_vkey.json
var vkey []byte

// GenECDSAaccountForTest generates a new ECDSA account and returns the private
// key, public key and address.
func GenECDSAaccountForTest() (*ecdsa.PrivateKey, ecdsa.PublicKey, common.Address, error) {
	// generate ecdsa keys and address (privKey and publicKey)
	privKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, ecdsa.PublicKey{}, common.Address{}, err
	}
	return privKey, privKey.PublicKey, crypto.PubkeyToAddress(privKey.PublicKey), nil
}

// SignECDSAForTest signs the data with the private key provided and returns the R and
// S values of the signature.
func SignECDSAForTest(privKey *ecdsa.PrivateKey, data []byte) (*big.Int, *big.Int, error) {
	sigBin, err := crypto.Sign(data, privKey)
	if err != nil {
		return nil, nil, err
	}
	// truncate the signature to 64 bytes (the first 32 bytes are the R value,
	// the second 32 bytes are the S value)
	sigBin = sigBin[:64]
	if valid := crypto.VerifySignature(crypto.CompressPubkey(&privKey.PublicKey), data, sigBin); !valid {
		return nil, nil, fmt.Errorf("invalid signature")
	}
	var sig gecdsa.Signature
	if _, err := sig.SetBytes(sigBin); err != nil {
		return nil, nil, err
	}
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])
	return r, s, nil
}

// GenEncryptionKeyForTest generates a new encryption key for testing
// purposes. It uses the Iden3 implementation of the BabyJubJub curve to
// simplify the process.
func GenEncryptionKeyForTest() ecc.Point {
	privkey := babyjub.NewRandPrivKey()

	x, y := privkey.Public().X, privkey.Public().Y
	return new(bjj.BJJ).SetPoint(x, y)
}

// GenBallotFieldsForTest generates a list of n random fields between min and max
// values. If unique is true, the fields will be unique.
func GenBallotFieldsForTest(n, max, min int, unique bool) []*big.Int {
	fields := []*big.Int{}
	stored := map[string]bool{}
	for i := 0; i < n; i++ {
		for {
			// generate random field
			field, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
			if err != nil {
				panic(err)
			}
			field.Add(field, big.NewInt(int64(min)))
			// if it should be unique and it's already stored, skip it,
			// otherwise add it to the list of fields and continue
			if !unique || !stored[field.String()] {
				fields = append(fields, field)
				stored[field.String()] = true
				break
			}
		}
	}
	return fields
}

// EncryptBallotFieldsForTest encrypts the fields provided using the public key and
// random k value provided. Each encrypted field includes two points (c1 and c2)
// that represent the encrypted field. The function also returns a list of the
// plain cipher fields (x and y values of c1 and c2) that simplify the process
// of hashing the inputs for the circuit.
func EncryptBallotFieldsForTest(fields []*big.Int, n int, pk ecc.Point, k *big.Int) ([][][]string, []*big.Int) {
	cipherfields := make([][][]string, n)
	plainCipherfields := []*big.Int{}
	for i := 0; i < n; i++ {
		if i < len(fields) {
			c1, c2, err := elgamal.EncryptWithK(pk, fields[i], k)
			if err != nil {
				panic(err)
			}
			c1X, c1Y := c1.Point()
			c2X, c2Y := c2.Point()
			cipherfields[i] = [][]string{
				{c1X.String(), c1Y.String()},
				{c2X.String(), c2Y.String()},
			}
			plainCipherfields = append(plainCipherfields, c1X, c1Y, c2X, c2Y)
		} else {
			cipherfields[i] = [][]string{
				{"0", "0"},
				{"0", "0"},
			}
			plainCipherfields = append(plainCipherfields, big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0))
		}
	}
	return cipherfields, plainCipherfields
}

// GenCommitmentAndNullifierForTest generates a commitment and nullifier for the
// given address, processID and secret values. It uses the Poseidon hash
// function over BabyJubJub curve to generate the commitment and nullifier.
// The commitment is generated using the address, processID and secret value,
// while the nullifier is generated using the commitment and secret value.
func GenCommitmentAndNullifierForTest(address, processID, secret []byte) (*big.Int, *big.Int, error) {
	commitment, err := poseidon.Hash([]*big.Int{
		util.BigToFF(new(big.Int).SetBytes(address)),
		util.BigToFF(new(big.Int).SetBytes(processID)),
		util.BigToFF(new(big.Int).SetBytes(secret)),
	})
	if err != nil {
		return nil, nil, err
	}
	nullifier, err := poseidon.Hash([]*big.Int{
		commitment,
		util.BigToFF(new(big.Int).SetBytes(secret)),
	})
	if err != nil {
		return nil, nil, err
	}
	return commitment, nullifier, nil
}

// CompileAndGenerateProofForTest compiles a circom circuit, generates the witness and
// generates the proof using the inputs provided. It returns the proof and the
// public signals of the proof. It uses Rapidsnark and Groth16 prover to
// generate the proof.
func CompileAndGenerateProofForTest(inputs []byte) (string, string, error) {
	finalInputs, err := witness.ParseInputs(inputs)
	if err != nil {
		return "", "", err
	}
	// instance witness calculator
	calc, err := witness.NewCircom2WitnessCalculator(circuit, true)
	if err != nil {
		return "", "", err
	}
	// calculate witness
	w, err := calc.CalculateWTNSBin(finalInputs, true)
	if err != nil {
		return "", "", err
	}
	// generate proof
	return prover.Groth16ProverRaw(pkey, w)
}

// VoterProofResult struct includes all the public information generated by the
// user after ballot proof generation. It includes the value of the given
// process id and address in the format used inside the circuit.
type VoterProofResult struct {
	ProcessID           *big.Int
	Address             *big.Int
	Nullifier           *big.Int
	Commitment          *big.Int
	EncryptedFields     [NFields][2][2]*big.Int
	PlainEcryptedFields []*big.Int
	Proof               *parser.GnarkRecursionProof
	InputsHash          *big.Int
}

// MockVoterForTest function return the information after proving a valid ballot
// for the voter address, process id and encryption key provided. It generates
// and encrypts the fields for the ballot, the nullifier and the commitment for
// the user and generates a proof of a valid vote. It returns a *VoterProofResult
// and an error if it fails.
func MockVoterForTest(address, processId []byte, encryptionKey ecc.Point) (*VoterProofResult, error) {
	// get encryption key coords
	encryptionKeyX, encryptionKeyY := encryptionKey.Point()
	// generate random fields
	fields := GenBallotFieldsForTest(MaxCount, MaxValue, MinValue, ForceUniqueness > 0)
	// encrypt the fields
	k, err := elgamal.RandK()
	if err != nil {
		return nil, err
	}
	strCipherfields, plainCipherfields := EncryptBallotFieldsForTest(fields, NFields, encryptionKey, k)
	// encode the cipherfields in big.Int's
	cipherfields := [NFields][2][2]*big.Int{}
	for i := 0; i < NFields; i++ {
		var ok bool
		cipherfields[i][0][0], ok = new(big.Int).SetString(strCipherfields[i][0][0], 10)
		if !ok {
			return nil, fmt.Errorf("error decoding encrypted field coordenate")
		}
		cipherfields[i][0][1], ok = new(big.Int).SetString(strCipherfields[i][0][1], 10)
		if !ok {
			return nil, fmt.Errorf("error decoding encrypted field coordenate")
		}
		cipherfields[i][1][0], ok = new(big.Int).SetString(strCipherfields[i][1][0], 10)
		if !ok {
			return nil, fmt.Errorf("error decoding encrypted field coordenate")
		}
		cipherfields[i][1][1], ok = new(big.Int).SetString(strCipherfields[i][1][1], 10)
		if !ok {
			return nil, fmt.Errorf("error decoding encrypted field coordenate")
		}
	}
	// generate and store voter nullifier and commitments
	secret := util.RandomBytes(16)
	commitment, nullifier, err := GenCommitmentAndNullifierForTest(address, processId, secret)
	if err != nil {
		return nil, err
	}
	ffAddress := arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(address))
	ffProcessID := arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(processId))
	// group the circom inputs to hash
	bigCircomInputs := []*big.Int{
		big.NewInt(int64(MaxCount)),
		big.NewInt(int64(ForceUniqueness)),
		big.NewInt(int64(MaxValue)),
		big.NewInt(int64(MinValue)),
		big.NewInt(int64(math.Pow(float64(MaxValue), float64(CostExp))) * int64(MaxCount)),
		big.NewInt(int64(MaxCount)),
		big.NewInt(int64(CostExp)),
		big.NewInt(int64(CostFromWeight)),
		ffAddress,
		big.NewInt(int64(Weight)),
		ffProcessID,
		encryptionKeyX,
		encryptionKeyY,
		nullifier,
		commitment,
	}
	bigCircomInputs = append(bigCircomInputs, plainCipherfields...)
	circomInputsHash, err := mimc7.Hash(bigCircomInputs, nil)
	if err != nil {
		return nil, err
	}
	// init circom inputs
	circomInputs := map[string]any{
		"fields":           circuits.BigIntArrayToStringArray(fields, NFields),
		"max_count":        fmt.Sprint(MaxCount),
		"force_uniqueness": fmt.Sprint(ForceUniqueness),
		"max_value":        fmt.Sprint(MaxValue),
		"min_value":        fmt.Sprint(MinValue),
		"max_total_cost":   fmt.Sprint(int(math.Pow(float64(MaxValue), float64(CostExp))) * MaxCount),
		"min_total_cost":   fmt.Sprint(MaxCount),
		"cost_exp":         fmt.Sprint(CostExp),
		"cost_from_weight": fmt.Sprint(CostFromWeight),
		"address":          ffAddress.String(),
		"weight":           fmt.Sprint(Weight),
		"process_id":       ffProcessID.String(),
		"pk":               []string{encryptionKeyX.String(), encryptionKeyY.String()},
		"k":                k.String(),
		"cipherfields":     strCipherfields,
		"nullifier":        nullifier.String(),
		"commitment":       commitment.String(),
		"secret":           arbo.BigToFF(arbo.BN254BaseField, new(big.Int).SetBytes(secret)).String(),
		"inputs_hash":      circomInputsHash.String(),
	}
	bCircomInputs, err := json.Marshal(circomInputs)
	if err != nil {
		return nil, err
	}
	// create the proof
	circomProof, err := Circom2GnarkProof(bCircomInputs)
	if err != nil {
		return nil, err
	}
	return &VoterProofResult{
		ProcessID:           ffProcessID,
		Address:             ffAddress,
		Nullifier:           nullifier,
		Commitment:          commitment,
		EncryptedFields:     cipherfields,
		PlainEcryptedFields: plainCipherfields,
		Proof:               circomProof,
		InputsHash:          circomInputsHash,
	}, nil
}
