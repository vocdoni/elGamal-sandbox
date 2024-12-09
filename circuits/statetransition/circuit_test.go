package statetransition_test

import (
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"
	"github.com/vocdoni/vocdoni-z-sandbox/circuits/statetransition"
)

func TestCircuitCompile(t *testing.T) {
	// enable log to see nbConstraints
	logger.Set(zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05"}).With().Timestamp().Logger())

	var fullCircuit statetransition.Circuit

	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &fullCircuit)
	if err != nil {
		panic(err)
	}
}
