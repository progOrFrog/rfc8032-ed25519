package ed25519

import (
	"crypto/sha512"
	"errors"
	"math/big"
)

func expandSeed(seed []byte) (*big.Int, []byte, error) {
	if len(seed) != 32 {
		return nil, nil, errors.New("bad seed length")
	}

	digest := sha512.Sum512(seed)
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	return fromLittleEndian(digest[:32]), digest[32:], nil
}

func hashToScalar(parts ...[]byte) *big.Int {
	h := sha512.New()
	for _, part := range parts {
		h.Write(part)
	}
	n := fromLittleEndian(h.Sum(nil))
	return n.Mod(n, L)
}

func Keygen(seed []byte) ([]byte, error) {
	priv, _, err := expandSeed(seed)
	if err != nil {
		return nil, err
	}
	return EncodePoint(ScalarMult(priv, BasePoint())), nil
}

func Sign(seed, msg []byte) ([]byte, error) {
	priv, prefix, err := expandSeed(seed)
	if err != nil {
		return nil, err
	}

	pub := EncodePoint(ScalarMult(priv, BasePoint()))

	nonce := hashToScalar(prefix, msg)
	R := EncodePoint(ScalarMult(nonce, BasePoint()))

	chal := hashToScalar(R, pub, msg)
	S := new(big.Int).Mul(chal, priv)
	S.Add(S, nonce)
	S.Mod(S, L)

	return append(R, toLittleEndian(S, 32)...), nil
}

func Verify(pub, msg, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 {
		return false
	}

	A, err := DecodePoint(pub)
	if err != nil {
		return false
	}
	R, err := DecodePoint(sig[:32])
	if err != nil {
		return false
	}
	S := fromLittleEndian(sig[32:])
	if S.Cmp(L) >= 0 {
		return false
	}

	chal := hashToScalar(sig[:32], pub, msg)

	eight := big.NewInt(8)
	left := ScalarMult(new(big.Int).Mul(eight, S), BasePoint())
	right := PointAdd(
		ScalarMult(eight, R),
		ScalarMult(new(big.Int).Mul(eight, chal), A),
	)

	return left.X.Cmp(right.X) == 0 && left.Y.Cmp(right.Y) == 0
}
