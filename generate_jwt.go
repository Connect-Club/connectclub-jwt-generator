package jwt_generator

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/google/uuid"
	"math/big"
	"runtime"
	"strings"
	"sync"
	"time"
)

const header = `{ "alg": "RS256", "typ": "JWT" }`

func parseBigInt(text string) *big.Int {
	v := big.NewInt(0)
	if err := v.UnmarshalText([]byte(text)); err != nil {
		panic(err)
	}
	return v
}

func encodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

var privKey *rsa.PrivateKey

func init() {
	privKey = getPrivateKey()
}

var lastTime time.Time
var lastJwt string
var generateJwtMu sync.Mutex

func GenerateJwt() string {
	generateJwtMu.Lock()
	defer generateJwtMu.Unlock()

	if !lastTime.IsZero() && time.Now().Sub(lastTime) < 30*time.Second {
		return lastJwt
	}

	lastTime = time.Now()

	payload := fmt.Sprintf(
		`{ "jti": "%v", "iat": %v, "os": "%v" }`,
		uuid.New().String(),
		lastTime.Unix(),
		runtime.GOOS,
	)

	sstr := strings.Join([]string{encodeSegment([]byte(header)), encodeSegment([]byte(payload))}, ".")
	hashed := sha256.Sum256([]byte(sstr))

	sign, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		panic(err)
	}

	lastJwt = strings.Join([]string{sstr, encodeSegment(sign)}, ".")
	return lastJwt
}
