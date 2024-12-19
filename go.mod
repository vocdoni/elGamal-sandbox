module github.com/vocdoni/vocdoni-z-sandbox

go 1.23.2

replace github.com/consensys/gnark => github.com/lucasmenendez/gnark v0.5.2-0.20241217104836-b7c9c2fcbe8c

require (
	github.com/consensys/gnark v0.11.1-0.20241210204654-a1e66c1d6b4d
	github.com/consensys/gnark-crypto v0.14.1-0.20241213223322-afee1955665f
	github.com/ethereum/go-ethereum v1.14.12
	github.com/frankban/quicktest v1.14.6
	github.com/go-chi/chi/v5 v5.1.0
	github.com/go-chi/cors v1.2.1
	github.com/iden3/go-iden3-crypto v0.0.17
	github.com/iden3/go-rapidsnark/prover v0.0.12
	github.com/iden3/go-rapidsnark/witness v0.0.6
	github.com/pressly/goose/v3 v3.21.1
	github.com/rs/zerolog v1.33.0
	github.com/vocdoni/arbo v0.0.0-20241216103934-e64315269b49
	github.com/vocdoni/circom2gnark v1.0.1-0.20241204100355-b93800bd88a4
	github.com/vocdoni/gnark-crypto-primitives v0.0.2-0.20241218124633-bd3f44d2cb73
	go.vocdoni.io/dvote v1.10.2-0.20241024102542-c1ce6d744bc5
)

require (
	github.com/DataDog/zstd v1.5.2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.14.3 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cockroachdb/errors v1.11.3 // indirect
	github.com/cockroachdb/fifo v0.0.0-20240606204812-0bbfbd93a7ce // indirect
	github.com/cockroachdb/logtags v0.0.0-20230118201751-21c54148d20b // indirect
	github.com/cockroachdb/pebble v1.1.2 // indirect
	github.com/cockroachdb/redact v1.1.5 // indirect
	github.com/cockroachdb/tokenbucket v0.0.0-20230807174530-cc333fc44b06 // indirect
	github.com/cometbft/cometbft v1.0.0-alpha.1 // indirect
	github.com/consensys/bavard v0.1.24 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dchest/blake512 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.3.0 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/getsentry/sentry-go v0.27.0 // indirect
	github.com/glendc/go-external-ip v0.1.0 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-logfmt/logfmt v0.6.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/snappy v0.0.5-0.20220116011046-fa5810519dcb // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20241101162523-b92577c0c142 // indirect
	github.com/holiman/uint256 v1.3.1 // indirect
	github.com/iden3/go-rapidsnark/types v0.0.3 // indirect
	github.com/iden3/wasmer-go v0.0.1 // indirect
	github.com/ingonyama-zk/icicle v1.1.0 // indirect
	github.com/ingonyama-zk/iciclegnark v0.1.0 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mfridman/interpolate v0.0.2 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/montanaflynn/stats v0.0.0-20171201202039-1bf9dbcd8cbe // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.19.1 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.55.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/ronanh/intcomp v1.1.0 // indirect
	github.com/sethvargo/go-retry v0.2.4 // indirect
	github.com/stretchr/testify v1.9.0 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20220614013038-64ee5596c38a // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20181117223130-1be2e3e5546d // indirect
	go.mongodb.org/mongo-driver v1.12.1 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/crypto v0.31.0 // indirect
	golang.org/x/exp v0.0.0-20240823005443-9b4947da3948 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.28.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	google.golang.org/protobuf v1.34.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)
