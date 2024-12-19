package aggregator

import (
	"errors"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

type dummyCircuit struct {
	nbConstraints int
	SecretInput   frontend.Variable `gnark:",secret"`
	PublicInputs  frontend.Variable `gnark:",public"`
}

func (c *dummyCircuit) Define(api frontend.API) error {
	cmtr, ok := api.(frontend.Committer)
	if !ok {
		return errors.New("api is not a commiter")
	}
	secret, err := cmtr.Commit(c.SecretInput)
	if err != nil {
		return err
	}
	api.AssertIsDifferent(secret, 0)

	res := api.Mul(c.SecretInput, c.SecretInput)
	for i := 2; i < c.nbConstraints; i++ {
		res = api.Mul(res, c.SecretInput)
	}
	api.AssertIsEqual(c.PublicInputs, res)
	return nil
}

// DummyPlaceholder function returns the placeholder of a dummy circtuit for
// the constraint.ConstraintSystem provided.
func DummyPlaceholder(mainCircuit constraint.ConstraintSystem) *dummyCircuit {
	return &dummyCircuit{nbConstraints: mainCircuit.GetNbConstraints()}
}

// DummyPlaceholder function returns the assigment of a dummy circtuit.
func DummyAssigment() *dummyCircuit {
	return &dummyCircuit{PublicInputs: 1, SecretInput: 1}
}
