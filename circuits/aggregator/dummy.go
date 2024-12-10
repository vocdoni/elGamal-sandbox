package aggregator

import "github.com/consensys/gnark/frontend"

type DummyCircuit struct {
	A  frontend.Variable `gnark:",public"`
	B  frontend.Variable `gnark:",public"`
	C  frontend.Variable `gnark:",public"`
	F1 frontend.Variable `gnark:"-"`
	F2 frontend.Variable `gnark:"-"`
}

func DummyWitness() *DummyCircuit {
	return &DummyCircuit{1, 1, 1, 0, 0}
}

func (c *DummyCircuit) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(c.A, 1)
	api.AssertIsLessOrEqual(c.B, 1)
	api.AssertIsLessOrEqual(c.C, 1)
	return nil
}
