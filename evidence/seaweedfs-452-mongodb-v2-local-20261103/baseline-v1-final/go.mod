module ouf.local/mongodb-v1-control

go 1.26.6

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/karlseguin/ccache/v2 v2.0.8 // indirect
	github.com/klauspost/compress v1.20.3 // indirect
	github.com/klauspost/reedsolomon v1.14.2 // indirect
	github.com/prometheus/client_golang v1.24.1 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.71.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/seaweedfs/goexif v1.0.3 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/viper v1.21.0 // indirect
	github.com/syndtr/goleveldb v1.0.1-0.20190318030020-c3a204f8e965 // indirect
	github.com/tylertreat/BoomFilters v0.0.0-20210315201527-1a82519a3e43 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/viant/ptrie v1.0.1 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.2.0 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	go.mongodb.org/mongo-driver v1.17.9
	golang.org/x/crypto v0.58.1-0.20261009181718-2f1f834330b2 // indirect
	golang.org/x/image v0.46.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	google.golang.org/grpc v1.86.0-dev.0.20261027044109-d619b5d02089 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cognusion/imaging v1.0.4 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	golang.org/x/sync v0.24.0 // indirect
	google.golang.org/grpc/security/advancedtls v1.0.0 // indirect
)

require (
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
)

require (
	github.com/go-jose/go-jose/v4 v4.1.6 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/montanaflynn/stats v0.7.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/pelletier/go-toml/v2 v2.4.3 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/sagikazarmark/locafero v0.11.0 // indirect
	github.com/sourcegraph/conc v0.3.1-0.20240121214520-5f936abd7ae8 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/spiffe/go-spiffe/v2 v2.8.2 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260921155816-b14227669459 // indirect
)

// replace github.com/seaweedfs/raft => /Users/chrislu/go/src/github.com/seaweedfs/raft

// tyler-smith/go-bip39 was deleted from GitHub, so `go mod download` fails for
// anyone resolving it directly (GOPROXY=direct). It only reaches us transitively
// through rclone's internxt backend, which calls IsMnemonicValid and NewSeed.
// cosmos/go-bip39 is a maintained, API-compatible fork.
replace github.com/tyler-smith/go-bip39 => github.com/cosmos/go-bip39 v1.0.0

require github.com/seaweedfs/seaweedfs v0.0.0

replace github.com/seaweedfs/seaweedfs => ../../maintained30-stage/source
