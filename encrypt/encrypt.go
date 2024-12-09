package encrypt

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/ecc"
	"github.com/vocdoni/vocdoni-z-sandbox/ecc/format"
)

// ElGamalCiphertext
type ElGamalCiphertext struct {
	C1, C2 *babyjub.Point
}

func NewElGamalCiphertext() *ElGamalCiphertext {
	return &ElGamalCiphertext{C1: babyjub.NewPoint(), C2: babyjub.NewPoint()}
}

func (z *ElGamalCiphertext) Encrypt(message *big.Int, publicKey *babyjub.PublicKey, k *big.Int) *ElGamalCiphertext {
	// c1 = [k] * G
	c1 := babyjub.NewPoint().Mul(k, babyjub.B8)
	// s = [k] * publicKey
	s := babyjub.NewPoint().Mul(k, publicKey.Point())
	// m = [message] * G
	m := babyjub.NewPoint().Mul(message, babyjub.B8)
	// c2 = m + s
	c2p := babyjub.NewPointProjective().Add(m.Projective(), s.Projective())
	z = &ElGamalCiphertext{
		C1: c1,
		C2: c2p.Affine(),
	}
	return z
}

func (z *ElGamalCiphertext) FromTEtoRTE() *ElGamalCiphertext {
	c1xRTE, c1yRTE := format.FromTEtoRTE(z.C1.X, z.C1.Y)
	c2xRTE, c2yRTE := format.FromTEtoRTE(z.C2.X, z.C2.Y)
	return &ElGamalCiphertext{
		C1: &babyjub.Point{
			X: c1xRTE,
			Y: c1yRTE,
		},
		C2: &babyjub.Point{
			X: c2xRTE,
			Y: c2yRTE,
		},
	}
}

func (z *ElGamalCiphertext) Add(x, y *ElGamalCiphertext) *ElGamalCiphertext {
	z.C1 = new(babyjub.PointProjective).Add(x.C1.Projective(), y.C1.Projective()).Affine()
	z.C2 = new(babyjub.PointProjective).Add(x.C2.Projective(), y.C2.Projective()).Affine()
	return z
}

func (z *ElGamalCiphertext) A1ToTEPoint() twistededwards.Point {
	return twistededwards.Point{
		X: z.C1.X,
		Y: z.C1.Y,
	}
}

func (z *ElGamalCiphertext) A2ToTEPoint() twistededwards.Point {
	return twistededwards.Point{
		X: z.C2.X,
		Y: z.C2.Y,
	}
}

// ToGnark returns a copy of hMsg, with the points reduced to reduced twisted edwards form
func (z *ElGamalCiphertext) ToGnark() elgamal.Ciphertext {
	return elgamal.Ciphertext{
		C1: z.FromTEtoRTE().A1ToTEPoint(),
		C2: z.FromTEtoRTE().A2ToTEPoint(),
	}
}

// BigInt serializes the content into a BigInt
func (hMsg ElGamalCiphertext) BigInt() *big.Int {
	return big.NewInt(0) // completely mock, of course
}

// ToRTE returns a copy of z, with the points reduced to reduced twisted edwards form
// func (z *Ciphertext) ToRTE() *Ciphertext {
// 	return &Ciphertext{
// 		C1: z.FromTEtoRTE().A1ToTEPoint(),
// 		C2: z.FromTEtoRTE().A2ToTEPoint(),
// 	}

// RandK function generates a random k value for encryption.
func RandK() (*big.Int, error) {
	kBytes := make([]byte, 20)
	_, err := rand.Read(kBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random k: %v", err)
	}
	k := new(big.Int).SetBytes(kBytes)
	return arbo.BigToFF(arbo.BN254BaseField, k), nil
}

// Encrypt function encrypts a message using the public key provided as
// elliptic curve point. It generates a random k and returns the two points
// that represent the encrypted message and the random k used to encrypt it.
// It returns an error if any.
func Encrypt(publicKey ecc.Point, msg *big.Int) (ecc.Point, ecc.Point, *big.Int, error) {
	k, err := RandK()
	if err != nil {
		return nil, nil, nil, err
	}
	// encrypt the message using the random k generated
	c1, c2 := EncryptWithK(publicKey, msg, k)
	return c1, c2, k, nil
}

// EncryptWithK function encrypts a message using the public key provided as
// elliptic curve point and the random k value provided. It returns the two
// points that represent the encrypted message and error if any.
func EncryptWithK(pubKey ecc.Point, msg, k *big.Int) (ecc.Point, ecc.Point) {
	order := pubKey.Order()
	// ensure the message is within the field
	msg.Mod(msg, order)
	// compute C1 = k * G
	c1 := pubKey.New()
	c1.ScalarBaseMult(k)
	// compute s = k * pubKey
	s := pubKey.New()
	s.ScalarMult(pubKey, k)
	// encode message as point M = message * G
	m := pubKey.New()
	m.ScalarBaseMult(msg)
	// compute C2 = M + s
	c2 := pubKey.New()
	c2.Add(m, s)
	return c1, c2
}
