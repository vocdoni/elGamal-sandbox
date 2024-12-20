package state

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/vocdoni/arbo"
	gelgamal "github.com/vocdoni/gnark-crypto-primitives/elgamal"
	"github.com/vocdoni/gnark-crypto-primitives/utils"

	garbo "github.com/vocdoni/gnark-crypto-primitives/tree/arbo"
	"github.com/vocdoni/gnark-crypto-primitives/tree/smt"
	"github.com/vocdoni/vocdoni-z-sandbox/crypto/elgamal"
	"github.com/vocdoni/vocdoni-z-sandbox/util"
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

// GenArboProof generates a ArboProof for the given key
func (o *State) GenArboProof(k []byte) (*ArboProof, error) {
	root, err := o.tree.Root()
	if err != nil {
		return nil, err
	}
	leafK, leafV, packedSiblings, existence, err := o.tree.GenProof(k)
	if err != nil {
		return nil, err
	}
	unpackedSiblings, err := arbo.UnpackSiblings(arbo.HashFunctionPoseidon, packedSiblings)
	if err != nil {
		return nil, err
	}
	return &ArboProof{
		Root:      root,
		Siblings:  unpackedSiblings,
		Key:       leafK,
		Value:     leafV,
		Existence: existence,
	}, nil
}

// ArboProofsFromAddOrUpdate generates an ArboProof before adding (or updating) the given leaf,
// and another ArboProof after updating, and returns both.
func (o *State) ArboProofsFromAddOrUpdate(k []byte, v []byte) (*ArboProof, *ArboProof, error) {
	mpBefore, err := o.GenArboProof(k)
	if err != nil {
		return nil, nil, err
	}
	if _, _, err := o.tree.Get(k); errors.Is(err, arbo.ErrKeyNotFound) {
		if err := o.tree.Add(k, v); err != nil {
			return nil, nil, fmt.Errorf("add key failed: %w", err)
		}
	} else {
		if err := o.tree.Update(k, v); err != nil {
			return nil, nil, fmt.Errorf("update key failed: %w", err)
		}
	}
	mpAfter, err := o.GenArboProof(k)
	if err != nil {
		return nil, nil, err
	}
	return mpBefore, mpAfter, nil
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

// GenMerkleProof generates a MerkleProof for the given key
func (o *State) GenMerkleProof(k []byte) (MerkleProof, error) {
	p, err := o.GenArboProof(k)
	if err != nil {
		return MerkleProof{}, err
	}
	return MerkleProofFromArboProof(p), nil
}

// MerkleProofFromArboProof converts an ArboProof into a MerkleProof
func MerkleProofFromArboProof(p *ArboProof) MerkleProof {
	padSiblings := func(unpackedSiblings [][]byte) [MaxLevels]frontend.Variable {
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

// Verify uses garbo.CheckInclusionProof to verify that:
//   - mp.Root matches passed root
//   - Key + Value belong to Root
func (mp *MerkleProof) VerifyProof(api frontend.API, hFn utils.Hasher, root frontend.Variable) {
	api.Println("verify proof", mp.String()) // TODO: remove this debug log

	api.AssertIsEqual(root, mp.Root)

	if err := garbo.CheckInclusionProof(api, hFn, mp.Key, mp.Value, mp.Root, mp.Siblings[:]); err != nil {
		panic(err)
	}
}

func (mp *MerkleProof) String() string {
	return fmt.Sprint(mp.Key, "=", mp.Value, " -> ", util.PrettyHex(mp.Root))
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

	// TODO: replace Is*ElGamal by a check on len(Ciphertext) or something?
	IsOldElGamal   frontend.Variable
	IsNewElGamal   frontend.Variable
	OldCiphertexts gelgamal.Ciphertexts
	NewCiphertexts gelgamal.Ciphertexts
}

// MerkleTransitionFromArboProofPair generates a MerkleTransition based on the pair of proofs passed
func MerkleTransitionFromArboProofPair(before, after *ArboProof) MerkleTransition {
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
		Siblings:       mpBefore.Siblings,
		OldRoot:        mpBefore.Root,
		OldKey:         mpBefore.Key,
		OldValue:       mpBefore.Value,
		NewRoot:        mpAfter.Root,
		NewKey:         mpAfter.Key,
		NewValue:       mpAfter.Value,
		IsOld0:         isOld0,
		Fnc0:           fnc0,
		Fnc1:           fnc1,
		IsOldElGamal:   0,
		IsNewElGamal:   0,
		OldCiphertexts: *gelgamal.NewCiphertexts(),
		NewCiphertexts: *gelgamal.NewCiphertexts(),
	}
}

// MerkleTransitionFromAddOrUpdate adds or updates a key in the tree,
// and returns a MerkleTransition.
func (o *State) MerkleTransitionFromAddOrUpdate(k []byte, v []byte) (MerkleTransition, error) {
	mpBefore, mpAfter, err := o.ArboProofsFromAddOrUpdate(k, v)
	if err != nil {
		return MerkleTransition{}, err
	}
	mp := MerkleTransitionFromArboProofPair(mpBefore, mpAfter)

	oldCiphertexts, newCiphertexts := elgamal.NewCiphertexts(Curve), elgamal.NewCiphertexts(Curve)
	if len(mpBefore.Value) > 32 {
		if err := oldCiphertexts.Deserialize(mpBefore.Value); err != nil {
			return MerkleTransition{}, err
		}
		mp.IsOldElGamal = 1
	}
	if len(mpAfter.Value) > 32 {
		if err := newCiphertexts.Deserialize(mpAfter.Value); err != nil {
			return MerkleTransition{}, err
		}
		mp.IsNewElGamal = 1
	}

	mp.OldCiphertexts = *oldCiphertexts.ToGnark()
	mp.NewCiphertexts = *newCiphertexts.ToGnark()

	return mp, nil
}

// MerkleTransitionFromNoop returns a NOOP MerkleTransition.
func (o *State) MerkleTransitionFromNoop() (MerkleTransition, error) {
	root, err := o.tree.Root()
	if err != nil {
		return MerkleTransition{}, err
	}
	mp := &ArboProof{
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
func (mp *MerkleTransition) Verify(api frontend.API, hFn utils.Hasher, oldRoot frontend.Variable) frontend.Variable {
	api.Println("verify transition", mp.String()) // TODO: remove this debug log

	api.AssertIsEqual(oldRoot, mp.OldRoot)

	hash1Old := api.Select(mp.IsOldElGamal,
		smt.Hash1(api, hFn, mp.OldKey, mp.OldCiphertexts.Serialize()...),
		smt.Hash1(api, hFn, mp.OldKey, mp.OldValue),
	)
	hash1New := api.Select(mp.IsNewElGamal,
		smt.Hash1(api, hFn, mp.NewKey, mp.NewCiphertexts.Serialize()...),
		smt.Hash1(api, hFn, mp.NewKey, mp.NewValue),
	)

	root := smt.ProcessorWithLeafHash(api, hFn,
		mp.OldRoot,
		mp.Siblings[:],
		mp.OldKey,
		hash1Old,
		mp.IsOld0,
		mp.NewKey,
		hash1New,
		mp.Fnc0,
		mp.Fnc1,
	)

	api.AssertIsEqual(root, mp.NewRoot)
	return mp.NewRoot
}

func (mp *MerkleTransition) String() string {
	return fmt.Sprint(util.PrettyHex(mp.OldRoot), " -> ", util.PrettyHex(mp.NewRoot), " | ",
		mp.OldKey, "=", mp.OldValue, " -> ", mp.NewKey, "=", mp.NewValue)
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
