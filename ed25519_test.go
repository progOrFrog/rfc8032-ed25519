package ed25519

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"math/big"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func onCurve(P Point) bool {
	x2 := modMul(P.X, P.X)
	y2 := modMul(P.Y, P.Y)
	left := modSub(y2, x2)
	right := modAdd(big.NewInt(1), modMul(d, modMul(x2, y2)))
	return left.Cmp(right) == 0
}

func samePoint(P, Q Point) bool {
	return P.X.Cmp(Q.X) == 0 && P.Y.Cmp(Q.Y) == 0
}

func validSignature(t *testing.T) (pub, msg, sig []byte) {
	t.Helper()
	seed := mustHex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	msg = []byte("hello")
	pub, err := Keygen(seed)
	if err != nil {
		t.Fatal(err)
	}
	sig, err = Sign(seed, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !Verify(pub, msg, sig) {
		t.Fatal("valid signature rejected")
	}
	return pub, msg, sig
}

func offCurveEncoding(t *testing.T) []byte {
	t.Helper()
	for y := int64(2); y < 100; y++ {
		data := toLittleEndian(big.NewInt(y), 32)
		if _, err := DecodePoint(data); err != nil && err.Error() == "point not on curve" {
			return data
		}
	}
	t.Fatal("no off-curve y found")
	return nil
}

func TestRFC8032Vectors(t *testing.T) {
	abc := sha512.Sum512([]byte("abc"))

	vectors := []struct {
		name string
		seed string
		pub  string
		msg  []byte
		sig  string
	}{
		{
			name: "TEST 1",
			seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			pub:  "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
			msg:  []byte{},
			sig:  "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
		},
		{
			name: "TEST 2",
			seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
			pub:  "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
			msg:  []byte{0x72},
			sig:  "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
		},
		{
			name: "TEST 3",
			seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
			pub:  "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
			msg:  []byte{0xaf, 0x82},
			sig:  "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
		},
		{
			name: "TEST SHA(abc)",
			seed: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
			pub:  "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
			msg:  abc[:],
			sig:  "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			seed := mustHex(t, v.seed)
			pub := mustHex(t, v.pub)
			sig := mustHex(t, v.sig)

			gotPub, err := Keygen(seed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotPub, pub) {
				t.Fatalf("pub = %x, want %x", gotPub, pub)
			}

			gotSig, err := Sign(seed, v.msg)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(gotSig, sig) {
				t.Fatalf("sig = %x, want %x", gotSig, sig)
			}

			if !Verify(pub, v.msg, sig) {
				t.Fatal("valid signature rejected")
			}
		})
	}
}

func TestBasePoint(t *testing.T) {
	B := BasePoint()
	if !onCurve(B) {
		t.Fatal("B is not on the curve")
	}
	if B.X.Bit(0) != 0 {
		t.Fatal("B.X is not even")
	}
	if B.Y.Cmp(modMul(big.NewInt(4), modInv(big.NewInt(5)))) != 0 {
		t.Fatal("B.Y != 4/5")
	}
	if !samePoint(ScalarMult(L, B), Identity()) {
		t.Fatal("[L]B != identity")
	}
}

func TestPointAdd(t *testing.T) {
	B := BasePoint()
	if !samePoint(PointAdd(B, Identity()), B) {
		t.Fatal("B + O != B")
	}
	a := big.NewInt(123456789)
	b := big.NewInt(987654321)
	sum := new(big.Int).Add(a, b)
	if !samePoint(ScalarMult(sum, B), PointAdd(ScalarMult(a, B), ScalarMult(b, B))) {
		t.Fatal("[a+b]B != [a]B + [b]B")
	}
	if !onCurve(PointAdd(B, B)) {
		t.Fatal("2B is not on the curve")
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	B := BasePoint()
	if hex.EncodeToString(EncodePoint(B)) != "5866666666666666666666666666666666666666666666666666666666666666" {
		t.Fatal("wrong encoding of B")
	}
	for i := int64(0); i < 20; i++ {
		P := ScalarMult(big.NewInt(i*7919), B)
		Q, err := DecodePoint(EncodePoint(P))
		if err != nil {
			t.Fatalf("k=%d: %v", i*7919, err)
		}
		if !samePoint(P, Q) {
			t.Fatalf("k=%d: round trip mismatch", i*7919)
		}
	}
}

func TestDecodeRejectsYOutOfRange(t *testing.T) {
	values := []*big.Int{
		p,
		new(big.Int).Add(p, big.NewInt(1)),
		new(big.Int).Sub(powerOfTwo(255), big.NewInt(1)),
	}
	for _, y := range values {
		_, err := DecodePoint(toLittleEndian(y, 32))
		if err == nil || err.Error() != "y out of range" {
			t.Fatalf("y=%v: got %v", y, err)
		}
	}
}

func TestDecodeRejectsPointNotOnCurve(t *testing.T) {
	data := offCurveEncoding(t)
	y := fromLittleEndian(data)
	x2 := modMul(modSub(modMul(y, y), big.NewInt(1)), modInv(modAdd(modMul(d, modMul(y, y)), big.NewInt(1))))
	if modExp(x2, new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2))).Cmp(big.NewInt(1)) == 0 {
		t.Fatalf("y=%v has a valid x", y)
	}
}

func TestDecodeRejectsInvalidXSign(t *testing.T) {
	data := EncodePoint(Identity())
	data[31] |= 0x80
	_, err := DecodePoint(data)
	if err == nil || err.Error() != "invalid x sign" {
		t.Fatalf("got %v", err)
	}
}

func TestDecodeRejectsBadLength(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		if _, err := DecodePoint(make([]byte, n)); err == nil {
			t.Fatalf("length %d accepted", n)
		}
	}
}

func TestVerifyRejectsSOutOfRange(t *testing.T) {
	pub, msg, sig := validSignature(t)
	S := fromLittleEndian(sig[32:])

	withSPlusL := append(append([]byte{}, sig[:32]...), toLittleEndian(new(big.Int).Add(S, L), 32)...)
	if Verify(pub, msg, withSPlusL) {
		t.Fatal("S + L accepted")
	}

	withL := append(append([]byte{}, sig[:32]...), toLittleEndian(L, 32)...)
	if Verify(pub, msg, withL) {
		t.Fatal("S = L accepted")
	}
}

func TestVerifyRejectsInvalidPoints(t *testing.T) {
	pub, msg, sig := validSignature(t)
	offCurve := offCurveEncoding(t)
	outOfRange := toLittleEndian(p, 32)

	for _, bad := range [][]byte{offCurve, outOfRange} {
		if Verify(bad, msg, sig) {
			t.Fatalf("invalid public key %x accepted", bad)
		}
		badSig := append(append([]byte{}, bad...), sig[32:]...)
		if Verify(pub, msg, badSig) {
			t.Fatalf("invalid R %x accepted", bad)
		}
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	pub, msg, sig := validSignature(t)

	if Verify(pub, []byte("hellO"), sig) {
		t.Fatal("wrong message accepted")
	}

	for _, i := range []int{0, 31, 32, 63} {
		badSig := append([]byte{}, sig...)
		badSig[i] ^= 1
		if Verify(pub, msg, badSig) {
			t.Fatalf("signature with flipped byte %d accepted", i)
		}
	}

	otherPub, err := Keygen(mustHex(t, "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
	if err != nil {
		t.Fatal(err)
	}
	if Verify(otherPub, msg, sig) {
		t.Fatal("signature accepted under another key")
	}
}

func TestBadLengths(t *testing.T) {
	if _, err := Keygen(make([]byte, 31)); err == nil {
		t.Fatal("Keygen accepted 31-byte seed")
	}
	if _, err := Sign(make([]byte, 33), nil); err == nil {
		t.Fatal("Sign accepted 33-byte seed")
	}
	pub, msg, sig := validSignature(t)
	if Verify(pub[:31], msg, sig) {
		t.Fatal("short public key accepted")
	}
	if Verify(pub, msg, sig[:63]) {
		t.Fatal("short signature accepted")
	}
}
