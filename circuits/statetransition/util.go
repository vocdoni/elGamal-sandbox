package statetransition

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark/frontend"
	"go.vocdoni.io/dvote/tree/arbo"
)

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
