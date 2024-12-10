package statetransition

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/elgamal"
	garbo "github.com/vocdoni/gnark-crypto-primitives/tree/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/tree/smt"
	"github.com/vocdoni/vocdoni-z-sandbox/encrypt"
)

const (
	// size of the inclusion proofs
	MaxLevels = 160
	// MaxKeyLen is ceil(maxLevels/8)
	MaxKeyLen = (MaxLevels + 7) / 8
)

// ArboProof stores the proof in arbo native types
type ArboProof struct {
	// Key+Value hashed through Siblings path, should produce Root hash
	Root      []byte
	Siblings  [][]byte
	Key       []byte
	Value     []byte
	Existence bool
}

func GenArboProof(t *arbo.Tree, k []byte) (ArboProof, error) {
	root, err := t.Root()
	if err != nil {
		return ArboProof{}, err
	}
	leafK, leafV, packedSiblings, existence, err := t.GenProof(k)
	if err != nil {
		return ArboProof{}, err
	}
	unpackedSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, packedSiblings)
	if err != nil {
		return ArboProof{}, err
	}
	return ArboProof{
		Root:      root,
		Siblings:  unpackedSiblings,
		Key:       leafK,
		Value:     leafV,
		Existence: existence,
	}, nil
}

// MerkleProof stores the leaf, the path, and the root hash.
type MerkleProof struct {
	// Key + Value hashed through Siblings path, should produce Root hash
	Root     frontend.Variable
	Siblings [MaxLevels]frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable
	Fnc      frontend.Variable // 0: inclusion, 1: non inclusion
}

func GenMerkleProof(t *arbo.Tree, k []byte) (MerkleProof, error) {
	p, err := GenArboProof(t, k)
	if err != nil {
		return MerkleProof{}, err
	}
	return MerkleProofFromArboProof(p), nil
}

func MerkleProofFromArboProof(p ArboProof) MerkleProof {
	fnc := 0 // inclusion
	if !p.Existence {
		fnc = 1 // non-inclusion
	}
	return MerkleProof{
		Root:     arbo.BytesToBigInt(p.Root),
		Siblings: padSiblings(p.Siblings),
		Key:      arbo.BytesToBigInt(p.Key),
		Value:    arbo.BytesToBigInt(p.Value),
		Fnc:      fnc,
	}
}

func padSiblings(unpackedSiblings [][]byte) [MaxLevels]frontend.Variable {
	paddedSiblings := [MaxLevels]frontend.Variable{}
	for i := range MaxLevels {
		if i < len(unpackedSiblings) {
			paddedSiblings[i] = arbo.BytesToBigInt(unpackedSiblings[i])
		} else {
			paddedSiblings[i] = big.NewInt(0)
		}
	}
	return paddedSiblings
}

// Verify uses garbo.CheckInclusionProof to verify that:
//   - mp.Root matches passed root
//   - Key + Value belong to Root
func (mp *MerkleProof) VerifyProof(api frontend.API, hFn garbo.Hash, root frontend.Variable) {
	api.AssertIsEqual(root, mp.Root)

	if err := garbo.CheckInclusionProof(api, hFn, mp.Key, mp.Value, mp.Root, mp.Siblings[:]); err != nil {
		panic(err)
	}
}

// MerkleTransition stores a pair of leaves and root hashes, and a single path common to both proofs
type MerkleTransition struct {
	// NewKey + NewValue hashed through Siblings path, should produce NewRoot hash
	NewRoot  frontend.Variable
	Siblings [MaxLevels]frontend.Variable
	NewKey   frontend.Variable
	NewValue frontend.Variable

	// OldKey + OldValue hashed through same Siblings should produce OldRoot hash
	OldRoot  frontend.Variable
	OldKey   frontend.Variable
	OldValue frontend.Variable
	IsOld0   frontend.Variable
	Fnc0     frontend.Variable
	Fnc1     frontend.Variable
}

// MerkleTransitionFromArboProofPair generates a MerkleTransition based on the pair of proofs passed
func MerkleTransitionFromArboProofPair(before, after ArboProof) MerkleTransition {
	//	Fnction
	//	fnc[0]  fnc[1]
	//	0       0       NOP
	//	0       1       UPDATE
	//	1       0       INSERT
	//	1       1       DELETE
	fnc0, fnc1 := 0, 0
	switch {
	case !before.Existence && !after.Existence: // exclusion, exclusion = NOOP
		fnc0, fnc1 = 0, 0
	case before.Existence && after.Existence: // inclusion, inclusion = UPDATE
		fnc0, fnc1 = 0, 1
	case !before.Existence && after.Existence: // exclusion, inclusion = INSERT
		fnc0, fnc1 = 1, 0
	case before.Existence && !after.Existence: // inclusion, exclusion = DELETE
		fnc0, fnc1 = 1, 1
	}

	isOld0 := 0
	if bytes.Equal(before.Key, []byte{}) && bytes.Equal(before.Value, []byte{}) {
		isOld0 = 1
	}

	mpBefore := MerkleProofFromArboProof(before)
	mpAfter := MerkleProofFromArboProof(after)
	return MerkleTransition{
		Siblings: mpBefore.Siblings,
		OldRoot:  mpBefore.Root,
		OldKey:   mpBefore.Key,
		OldValue: mpBefore.Value,
		NewRoot:  mpAfter.Root,
		NewKey:   mpAfter.Key,
		NewValue: mpAfter.Value,
		IsOld0:   isOld0,
		Fnc0:     fnc0,
		Fnc1:     fnc1,
	}
}

// MerkleTransitionFromAddOrUpdate adds or updates a key in the tree,
// and returns a MerkleTransition.
func MerkleTransitionFromAddOrUpdate(t *arbo.Tree, k []byte, v []byte) (MerkleTransition, error) {
	mpBefore, err := GenArboProof(t, k)
	if err != nil {
		return MerkleTransition{}, err
	}
	if _, _, err := t.Get(k); errors.Is(err, arbo.ErrKeyNotFound) {
		if err := t.Add(k, v); err != nil {
			return MerkleTransition{}, fmt.Errorf("add key failed: %w", err)
		}
	} else {
		if err := t.Update(k, v); err != nil {
			return MerkleTransition{}, fmt.Errorf("update key failed: %w", err)
		}
	}
	mpAfter, err := GenArboProof(t, k)
	if err != nil {
		return MerkleTransition{}, err
	}
	return MerkleTransitionFromArboProofPair(mpBefore, mpAfter), nil
}

// MerkleTransitionFromNoop returns a NOOP MerkleTransition.
func MerkleTransitionFromNoop(t *arbo.Tree) (MerkleTransition, error) {
	root, err := t.Root()
	if err != nil {
		return MerkleTransition{}, err
	}
	mp := ArboProof{
		Root:      root,
		Siblings:  [][]byte{},
		Key:       []byte{},
		Value:     []byte{},
		Existence: false,
	}
	return MerkleTransitionFromArboProofPair(mp, mp), nil
}

// Verify uses smt.Processor to verify that:
//   - mp.OldRoot matches passed oldRoot
//   - OldKey + OldValue belong to OldRoot
//   - NewKey + NewValue belong to NewRoot
//   - no other changes were introduced between OldRoot -> NewRoot
//
// and returns mp.NewRoot
func (mp *MerkleTransition) Verify(api frontend.API, oldRoot frontend.Variable) frontend.Variable {
	mp.printDebugLog(api)

	api.AssertIsEqual(oldRoot, mp.OldRoot)

	root := smt.Processor(api,
		mp.OldRoot,
		mp.Siblings[:],
		mp.OldKey,
		mp.OldValue,
		mp.IsOld0,
		mp.NewKey,
		mp.NewValue,
		mp.Fnc0,
		mp.Fnc1,
	)

	api.AssertIsEqual(root, mp.NewRoot)
	return mp.NewRoot
}

func (mp *MerkleTransition) printDebugLog(api frontend.API) {
	api.Println("verify transition", prettyHex(mp.OldRoot), "->", prettyHex(mp.NewRoot), "|",
		mp.OldKey, "=", mp.OldValue, "->", mp.NewKey, "=", mp.NewValue)
}

// IsUpdate returns true when mp.Fnc0 == 0 && mp.Fnc1 == 1
func (mp *MerkleTransition) IsUpdate(api frontend.API) frontend.Variable {
	fnc0IsZero := api.IsZero(mp.Fnc0)
	fnc1IsOne := api.Sub(1, api.IsZero(mp.Fnc1))
	return api.And(fnc0IsZero, fnc1IsOne)
}

// IsInsert returns true when mp.Fnc0 == 1 && mp.Fnc1 == 0
func (mp *MerkleTransition) IsInsert(api frontend.API) frontend.Variable {
	fnc0IsOne := api.Sub(1, api.IsZero(mp.Fnc0))
	fnc1IsZero := api.IsZero(mp.Fnc1)
	return api.And(fnc1IsZero, fnc0IsOne)
}

// IsInsertOrUpdate returns true when IsInsert or IsUpdate is true
func (mp *MerkleTransition) IsInsertOrUpdate(api frontend.API) frontend.Variable {
	return api.Or(mp.IsInsert(api), mp.IsUpdate(api))
}

type MerkleTransitionElGamal struct {
	MerkleTransition
	OldCiphertext elgamal.Ciphertext
	NewCiphertext elgamal.Ciphertext
}

// MerkleTransitionFromNoop returns a NOOP MerkleTransition.
func MerkleTransitionElGamalFromNoop(t *arbo.Tree) (MerkleTransitionElGamal, error) {
	mp, err := MerkleTransitionFromNoop(t)
	if err != nil {
		return MerkleTransitionElGamal{}, err
	}
	return MerkleTransitionElGamal{
		MerkleTransition: mp,
		NewCiphertext:    encrypt.NewElGamalCiphertext().ToGnark(),
		OldCiphertext:    encrypt.NewElGamalCiphertext().ToGnark(),
	}, nil
}

// IsUpdate returns true when mp.Fnc0 == 0 && mp.Fnc1 == 1
func (mp *MerkleTransitionElGamal) IsUpdate(api frontend.API) frontend.Variable {
	return mp.MerkleTransition.IsUpdate(api)
}

// IsInsert returns true when mp.Fnc0 == 1 && mp.Fnc1 == 0
func (mp *MerkleTransitionElGamal) IsInsert(api frontend.API) frontend.Variable {
	return mp.MerkleTransition.IsInsert(api)
}

// IsInsertOrUpdate returns true when IsInsert or IsUpdate is true
func (mp *MerkleTransitionElGamal) IsInsertOrUpdate(api frontend.API) frontend.Variable {
	return mp.MerkleTransition.IsInsertOrUpdate(api)
}
