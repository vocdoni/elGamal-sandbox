package statetransition_test

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/test"
	"github.com/rs/zerolog"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/statetransition"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/state"

	"github.com/vocdoni/arbo"
	"go.vocdoni.io/dvote/db/metadb"
)

func TestCircuitCompile(t *testing.T) {
	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &statetransition.Circuit{})
	if err != nil {
		panic(err)
	}
}

func TestCircuitProve(t *testing.T) {
	s := newMockState(t)

	// first batch
	if err := s.StartBatch(); err != nil {
		t.Fatal(err)
	}
	if err := s.AddVote(newMockVote(1, 10)); err != nil { // new vote 1
		t.Fatal(err)
	}
	if err := s.AddVote(newMockVote(2, 20)); err != nil { // new vote 2
		t.Fatal(err)
	}
	witness, err := GenerateWitnesses(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EndBatch(); err != nil { // expected result: 16+17=33
		t.Fatal(err)
	}
	assert := test.NewAssert(t)

	assert.ProverSucceeded(
		&statetransition.Circuit{},
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

	debugLog(t, witness)

	// second batch
	if err := s.StartBatch(); err != nil {
		t.Fatal(err)
	}
	if err := s.AddVote(newMockVote(1, 100)); err != nil { // overwrite vote 1
		t.Fatal(err)
	}
	if err := s.AddVote(newMockVote(3, 30)); err != nil { // add vote 3
		t.Fatal(err)
	}
	if err := s.AddVote(newMockVote(4, 30)); err != nil { // add vote 4
		t.Fatal(err)
	}
	witness, err = GenerateWitnesses(s)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.EndBatch(); err != nil {
		t.Fatal(err)
	}
	// expected results:
	// ResultsAdd: 16+17+10+100 = 143
	// ResultsSub: 16 = 16
	// Final: 16+17-16+10+100 = 127
	assert.ProverSucceeded(
		&statetransition.Circuit{},
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

	debugLog(t, witness)
}

func debugLog(t *testing.T, witness *statetransition.Circuit) {
	// js, _ := json.MarshalIndent(witness, "", "  ")
	// fmt.Printf("\n\n%s\n\n", js)
	t.Log("public: RootHashBefore", prettyHex(witness.RootHashBefore))
	t.Log("public: RootHashAfter", prettyHex(witness.RootHashAfter))
	t.Log("public: NumVotes", prettyHex(witness.NumNewVotes))
	t.Log("public: NumOverwrites", prettyHex(witness.NumOverwrites))
	for name, mt := range map[string]state.MerkleTransition{
		"ResultsAdd": witness.ResultsAdd,
		"ResultsSub": witness.ResultsSub,
	} {
		t.Log(name, "transitioned", "(root", prettyHex(mt.OldRoot), "->", prettyHex(mt.NewRoot), ")",
			"value", mt.OldValue, "->", mt.NewValue,
		)
		for i := range mt.OldCiphertexts {
			t.Log(name, i, "elgamal.C1.X", mt.OldCiphertexts[i].C1.X, "->", mt.NewCiphertexts[i].C1.X)
			t.Log(name, i, "elgamal.C1.Y", mt.OldCiphertexts[i].C1.Y, "->", mt.NewCiphertexts[i].C1.Y)
			t.Log(name, i, "elgamal.C2.X", mt.OldCiphertexts[i].C2.X, "->", mt.NewCiphertexts[i].C2.X)
			t.Log(name, i, "elgamal.C2.Y", mt.OldCiphertexts[i].C2.Y, "->", mt.NewCiphertexts[i].C2.Y)
		}
	}
}

func prettyHex(v frontend.Variable) string {
	type hasher interface {
		HashCode() [16]byte
	}
	switch v := v.(type) {
	case (*big.Int):
		return hex.EncodeToString(arbo.BigIntToBytes(32, v)[:4])
	case int:
		return fmt.Sprintf("%d", v)
	case []byte:
		return fmt.Sprintf("%x", v[:4])
	case hasher:
		return fmt.Sprintf("%x", v.HashCode())
	default:
		return fmt.Sprintf("(%v)=%+v", reflect.TypeOf(v), v)
	}
}

type CircuitBallots struct {
	statetransition.Circuit
}

func (circuit CircuitBallots) Define(api frontend.API) error {
	circuit.VerifyBallots(api)
	return nil
}

func TestCircuitBallotsCompile(t *testing.T) {
	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &CircuitBallots{})
	if err != nil {
		panic(err)
	}
}

func TestCircuitBallotsProve(t *testing.T) {
	s := newMockState(t)

	if err := s.StartBatch(); err != nil {
		t.Fatal(err)
	}

	if err := s.AddVote(newMockVote(1, 10)); err != nil { // new vote 1
		t.Fatal(err)
	}

	witness, err := GenerateWitnesses(s)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.EndBatch(); err != nil { // expected result: 16+17=33
		t.Fatal(err)
	}
	assert := test.NewAssert(t)

	assert.ProverSucceeded(
		&CircuitBallots{},
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))
}

type CircuitMerkleTransitions struct {
	statetransition.Circuit
}

func (circuit CircuitMerkleTransitions) Define(api frontend.API) error {
	circuit.VerifyMerkleTransitions(api, statetransition.HashFn)
	return nil
}

func TestCircuitMerkleTransitionsCompile(t *testing.T) {
	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &CircuitMerkleTransitions{})
	if err != nil {
		panic(err)
	}
}

func TestCircuitMerkleTransitionsProve(t *testing.T) {
	s := newMockState(t)

	if err := s.StartBatch(); err != nil {
		t.Fatal(err)
	}

	if err := s.AddVote(newMockVote(1, 10)); err != nil {
		t.Fatal(err)
	}

	witness, err := GenerateWitnesses(s)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.EndBatch(); err != nil {
		t.Fatal(err)
	}

	assert := test.NewAssert(t)

	assert.ProverSucceeded(
		&CircuitMerkleTransitions{},
		witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

	debugLog(t, witness)
}

func newMockState(t *testing.T) *state.State {
	s, err := state.New(metadb.NewTest(t),
		[]byte{0xca, 0xfe, 0x00})
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Initialize(
		[]byte{0xca, 0xfe, 0x01},
		[]byte{0xca, 0xfe, 0x02},
		[]byte{0xca, 0xfe, 0x03},
	); err != nil {
		t.Fatal(err)
	}

	return s
}

const (
	mockNullifiersOffset = 100
	mockAddressesOffset  = 200
)

// newMockVote creates a new vote
func newMockVote(index, amount int64) *state.Vote {
	nullifier := arbo.BigIntToBytes(state.MaxKeyLen,
		big.NewInt(int64(index)+int64(mockNullifiersOffset))) // mock

	// generate a public mocked key
	publicKey, _, err := elgamal.GenerateKey(state.Curve)
	if err != nil {
		panic(fmt.Errorf("error generating public key: %v", err))
	}

	ballot, err := elgamal.NewCiphertexts(publicKey).Encrypt(
		[elgamal.NumCiphertexts]*big.Int{
			big.NewInt(int64(amount)),
			big.NewInt(int64(amount)),
		},
		publicKey, nil)
	if err != nil {
		panic(fmt.Errorf("error encrypting: %v", err))
	}

	address := arbo.BigIntToBytes(state.MaxKeyLen,
		big.NewInt(int64(index)+int64(mockAddressesOffset))) // mock
	commitment := big.NewInt(amount + 256)

	return &state.Vote{
		Nullifier:  nullifier,
		Ballot:     ballot,
		Address:    address,
		Commitment: commitment,
	}
}
