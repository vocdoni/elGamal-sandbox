package util

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/arbo"
)

// RandomBytes generates a random byte slice of length n.
func RandomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

// Random32 generates a random 32-byte array.
func Random32() [32]byte {
	var bytes [32]byte
	copy(bytes[:], RandomBytes(32))
	return bytes
}

// RandomHex generates a random hex string of length n.
func RandomHex(n int) string {
	return fmt.Sprintf("%x", RandomBytes(n))
}

// RandomInt generates a random integer between min and max.
func RandomInt(min, max int) int {
	num, err := rand.Int(rand.Reader, big.NewInt(int64(max-min)))
	if err != nil {
		panic(err)
	}
	return int(num.Int64()) + min
}

// TrimHex trims the '0x' prefix from a hex string.
func TrimHex(s string) string {
	if len(s) >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X') {
		return s[2:]
	}
	return s
}

// bn254BaseField contains the Base Field of the twisted Edwards curve, whose
// base field os the scalar field on the curve BN254. It helps to represent
// a scalar number into the field.
var bn254BaseField, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

// BigToFF function returns the finite field representation of the big.Int
// provided. It uses Euclidean Modulus and the BN254 curve scalar field to
// represent the provided number.
func BigToFF(iv *big.Int) *big.Int {
	z := big.NewInt(0)
	if c := iv.Cmp(bn254BaseField); c == 0 {
		return z
	} else if c != 1 && iv.Cmp(z) != -1 {
		return iv
	}
	return z.Mod(iv, bn254BaseField)
}

func PrettyHex(v frontend.Variable) string {
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
