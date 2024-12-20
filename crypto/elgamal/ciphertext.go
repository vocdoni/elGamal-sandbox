package elgamal

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/vocdoni/arbo"
	gelgamal "github.com/vocdoni/gnark-crypto-primitives/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/ecc/format"
)

// NumCiphertexts represents how many Ciphertexts are grouped
const NumCiphertexts = 2

// sizes in bytes needed to serialize Ciphertexts
const (
	sizeCoord       = 32
	sizePoint       = 2 * sizeCoord
	SizeCiphertext  = 2 * sizePoint
	SizeCiphertexts = NumCiphertexts * SizeCiphertext
)

type Ciphertexts [NumCiphertexts]*Ciphertext

func NewCiphertexts(curve ecc.Point) *Ciphertexts {
	cs := &Ciphertexts{}
	for i := range cs {
		cs[i] = NewCiphertext(curve)
	}
	return cs
}

// Encrypt encrypts a message using the public key provided as elliptic curve point.
// The randomness k can be provided or nil to generate a new one.
func (cs *Ciphertexts) Encrypt(message [NumCiphertexts]*big.Int, publicKey ecc.Point, k *big.Int) (*Ciphertexts, error) {
	for i := range cs {
		if _, err := cs[i].Encrypt(message[i], publicKey, k); err != nil {
			return nil, err
		}
	}
	return cs, nil
}

// Add adds two Ciphertexts and stores the result in the receiver, which is also returned.
func (cs *Ciphertexts) Add(x, y *Ciphertexts) *Ciphertexts {
	for i := range cs {
		cs[i].Add(x[i], y[i])
	}
	return cs
}

// Serialize returns a slice of len N*4*32 bytes,
// representing each Ciphertext C1.X, C1.Y, C2.X, C2.Y as little-endian,
// in reduced twisted edwards form.
func (cs *Ciphertexts) Serialize() []byte {
	var buf bytes.Buffer
	for _, z := range cs {
		buf.Write(z.Serialize())
	}
	return buf.Bytes()
}

// Deserialize reconstructs a Ciphertexts from a slice of bytes.
// The input must be of len N*4*32 bytes (otherwise it returns an error),
// representing each Ciphertext C1.X, C1.Y, C2.X, C2.Y as little-endian,
// in reduced twisted edwards form.
func (cs *Ciphertexts) Deserialize(data []byte) error {
	// Validate the input length
	if len(data) != SizeCiphertexts {
		return fmt.Errorf("invalid input length: got %d bytes, expected %d bytes", len(data), SizeCiphertexts)
	}
	for i := range cs {
		err := cs[i].Deserialize(data[i*SizeCiphertext : (i+1)*SizeCiphertext])
		if err != nil {
			return err
		}
	}
	return nil
}

// TODO: implement Marshal, Unmarshal, String for Ciphertexts
// // Marshal converts Ciphertexts to a byte slice.
// func (z *Ciphertexts) Marshal() ([]byte, error) {
// 	return json.Marshal(z)
// }

// // Unmarshal populates Ciphertexts from a byte slice.
// func (z *Ciphertexts) Unmarshal(data []byte) error {
// 	return json.Unmarshal(data, z)
// }

// // String returns a string representation of the Ciphertexts.
// func (z *Ciphertexts) String() string {
// 	if z == nil || z.C1 == nil || z.C2 == nil {
// 		return "{C1: nil, C2: nil}"
// 	}
// 	return fmt.Sprintf("{C1: %s, C2: %s}", z.C1.String(), z.C2.String())
// }

// ToGnark returns cs as the struct used by gnark,
// with the points in reduced twisted edwards format
func (cs *Ciphertexts) ToGnark() *gelgamal.Ciphertexts {
	gcs := &gelgamal.Ciphertexts{}
	for i := range cs {
		gcs[i] = *cs[i].ToGnark()
	}
	return gcs
}

// Ciphertext represents an ElGamal encrypted message with homomorphic properties.
// It is a wrapper for convenience of the elGamal ciphersystem that encapsulates the two points of a ciphertext.
type Ciphertext struct {
	C1 ecc.Point `json:"c1"`
	C2 ecc.Point `json:"c2"`
}

// NewCiphertext creates a new Ciphertext on the same curve as the given Point.
// The Point must be one on of the supported curves by crypto/ecc/curves package,
// can be easily created with curves.New(type)
func NewCiphertext(curve ecc.Point) *Ciphertext {
	return &Ciphertext{C1: curve.New(), C2: curve.New()}
}

// Encrypt encrypts a message using the public key provided as elliptic curve point.
// The randomness k can be provided or nil to generate a new one.
func (z *Ciphertext) Encrypt(message *big.Int, publicKey ecc.Point, k *big.Int) (*Ciphertext, error) {
	var err error
	if k == nil {
		k, err = RandK()
		if err != nil {
			return nil, fmt.Errorf("elgamal encryption failed: %w", err)
		}
	}
	c1, c2, err := EncryptWithK(publicKey, message, k)
	if err != nil {
		return nil, fmt.Errorf("elgamal encryption failed: %w", err)
	}
	z.C1 = c1
	z.C2 = c2
	return z, nil
}

// Add adds two Ciphertext and stores the result in z, which is also returned.
func (z *Ciphertext) Add(x, y *Ciphertext) *Ciphertext {
	z.C1.SafeAdd(x.C1, y.C1)
	z.C2.SafeAdd(x.C2, y.C2)
	return z
}

// Serialize returns a slice of len 4*32 bytes,
// representing the C1.X, C1.Y, C2.X, C2.Y as little-endian,
// in reduced twisted edwards form.
func (z *Ciphertext) Serialize() []byte {
	var buf bytes.Buffer
	// TODO: we wouldn't need the format conversion if Point() returns the correct format
	c1x, c1y := format.FromTEtoRTE(z.C1.Point())
	c2x, c2y := format.FromTEtoRTE(z.C2.Point())
	for _, bi := range []*big.Int{c1x, c1y, c2x, c2y} {
		buf.Write(arbo.BigIntToBytes(sizeCoord, bi))
	}
	return buf.Bytes()
}

// Deserialize reconstructs an Ciphertext from a slice of bytes.
// The input must be of len 4*32 bytes (otherwise it returns an error),
// representing the C1.X, C1.Y, C2.X, C2.Y as little-endian,
// in reduced twisted edwards form.
func (z *Ciphertext) Deserialize(data []byte) error {
	// Validate the input length
	if len(data) != SizeCiphertext {
		return fmt.Errorf("invalid input length: got %d bytes, expected %d bytes", len(data), SizeCiphertext)
	}

	// Helper function to extract *big.Int from a serialized slice
	readBigInt := func(offset int) *big.Int {
		return arbo.BytesToBigInt(data[offset : offset+sizeCoord])
	}
	// Deserialize each field
	// TODO: we wouldn't need the format conversion if SetPoint() accepts the correct format
	z.C1 = z.C1.SetPoint(format.FromRTEtoTE(
		readBigInt(0*sizeCoord),
		readBigInt(1*sizeCoord),
	))
	z.C2 = z.C2.SetPoint(format.FromRTEtoTE(
		readBigInt(2*sizeCoord),
		readBigInt(3*sizeCoord),
	))
	return nil
}

// Marshal converts Ciphertext to a byte slice.
func (z *Ciphertext) Marshal() ([]byte, error) {
	return json.Marshal(z)
}

// Unmarshal populates Ciphertext from a byte slice.
func (z *Ciphertext) Unmarshal(data []byte) error {
	return json.Unmarshal(data, z)
}

// String returns a string representation of the Ciphertext.
func (z *Ciphertext) String() string {
	if z == nil || z.C1 == nil || z.C2 == nil {
		return "{C1: nil, C2: nil}"
	}
	return fmt.Sprintf("{C1: %s, C2: %s}", z.C1.String(), z.C2.String())
}

// ToGnark returns z as the struct used by gnark,
// with the points in reduced twisted edwards format
func (z *Ciphertext) ToGnark() *gelgamal.Ciphertext {
	// TODO: we wouldn't need the format conversion if Point() returns the correct format
	c1x, c1y := format.FromTEtoRTE(z.C1.Point())
	c2x, c2y := format.FromTEtoRTE(z.C2.Point())
	return &gelgamal.Ciphertext{
		C1: twistededwards.Point{X: c1x, Y: c1y},
		C2: twistededwards.Point{X: c2x, Y: c2y},
	}
}
