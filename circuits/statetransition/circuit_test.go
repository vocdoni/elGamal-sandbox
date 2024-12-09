package statetransition_test

import (
	"encoding/hex"
	"encoding/json"
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

	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/tree/arbo"
)

func TestCircuitCompile(t *testing.T) {
	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &statetransition.Circuit{})
	if err != nil {
		panic(err)
	}
}

func TestCircuit(t *testing.T) {
	state, err := NewState(metadb.NewTest(t),
		[]byte{0xca, 0xfe, 0x00},
		[]byte{0xca, 0xfe, 0x01},
		[]byte{0xca, 0xfe, 0x02},
		[]byte{0xca, 0xfe, 0x03},
	)
	if err != nil {
		t.Fatal(err)
	}
	// first batch
	if err := state.StartBatch(); err != nil {
		t.Fatal(err)
	}
	if err := state.AddVote(NewVote(1, 10)); err != nil { // new vote 1
		t.Fatal(err)
	}
	if err := state.AddVote(NewVote(2, 20)); err != nil { // new vote 2
		t.Fatal(err)
	}
	if err := state.EndBatch(); err != nil { // expected result: 16+17=33
		t.Fatal(err)
	}
	assert := test.NewAssert(t)

	assert.ProverSucceeded(
		&statetransition.Circuit{},
		&state.Witnesses,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

	debugLog(t, state)

	// second batch
	if err := state.StartBatch(); err != nil {
		t.Fatal(err)
	}
	if err := state.AddVote(NewVote(1, 100)); err != nil { // overwrite vote 1
		t.Fatal(err)
	}
	if err := state.AddVote(NewVote(3, 30)); err != nil { // add vote 3
		t.Fatal(err)
	}
	if err := state.AddVote(NewVote(4, 30)); err != nil { // add vote 4
		t.Fatal(err)
	}
	if err := state.EndBatch(); err != nil {
		t.Fatal(err)
	}
	// expected results:
	// ResultsAdd: 16+17+10+100 = 143
	// ResultsSub: 16 = 16
	// Final: 16+17-16+10+100 = 127
	assert.ProverSucceeded(
		&statetransition.Circuit{},
		&state.Witnesses,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))

	debugLog(t, state)
}

func debugLog(t *testing.T, state State) {
	t.Log("public: RootHashBefore", prettyHex(state.Witnesses.RootHashBefore))
	t.Log("public: RootHashAfter", prettyHex(state.Witnesses.RootHashAfter))
	t.Log("public: NumVotes", prettyHex(state.Witnesses.NumNewVotes))
	t.Log("public: NumOverwrites", prettyHex(state.Witnesses.NumOverwrites))
	for name, mt := range map[string]statetransition.MerkleTransitionElGamal{
		"ResultsAdd": state.Witnesses.ResultsAdd,
		"ResultsSub": state.Witnesses.ResultsSub,
	} {
		t.Log(name, "transitioned", "(root", prettyHex(mt.OldRoot), "->", prettyHex(mt.NewRoot), ")",
			"value", mt.OldValue, "->", mt.NewValue,
		)
		t.Log(name, "elgamal.C1.X", mt.OldCiphertext.C1.X, "->", mt.NewCiphertext.C1.X)
		t.Log(name, "elgamal.C1.Y", mt.OldCiphertext.C1.Y, "->", mt.NewCiphertext.C1.Y)
		t.Log(name, "elgamal.C2.X", mt.OldCiphertext.C2.X, "->", mt.NewCiphertext.C2.X)
		t.Log(name, "elgamal.C2.Y", mt.OldCiphertext.C2.Y, "->", mt.NewCiphertext.C2.Y)
	}
}

func debugWitness(witness statetransition.Circuit) {
	js, _ := json.MarshalIndent(witness, "", "  ")
	fmt.Printf("\n\n%s\n\n", js)
}

func prettyHex(v frontend.Variable) string {
	type hasher interface {
		HashCode() [16]byte
	}
	switch v := v.(type) {
	case (*big.Int):
		return hex.EncodeToString(arbo.BigIntToBytesLE(32, v)[:4])
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

func TestCircuitBallots(t *testing.T) {
	state, err := NewState(metadb.NewTest(t),
		[]byte{0xca, 0xfe, 0x00},
		[]byte{0xca, 0xfe, 0x01},
		[]byte{0xca, 0xfe, 0x02},
		[]byte{0xca, 0xfe, 0x03},
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := state.AddVote(NewVote(1, 10)); err != nil { // new vote 1
		t.Fatal(err)
	}

	if err := state.EndBatch(); err != nil { // expected result: 16+17=33
		t.Fatal(err)
	}
	assert := test.NewAssert(t)

	assert.ProverSucceeded(
		&CircuitBallots{},
		&state.Witnesses,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16))
}
