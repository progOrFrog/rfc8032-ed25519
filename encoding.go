package ed25519

import (
	"errors"
	"math/big"
)

func toLittleEndian(n *big.Int, size int) []byte {
	bigEndian := n.Bytes()
	buf := make([]byte, size)
	for i, b := range bigEndian {
		buf[len(bigEndian)-1-i] = b
	}
	return buf
}

func fromLittleEndian(data []byte) *big.Int {
	bigEndian := make([]byte, len(data))
	for i, b := range data {
		bigEndian[len(data)-1-i] = b
	}
	return new(big.Int).SetBytes(bigEndian)
}

func EncodePoint(P Point) []byte {
	buf := toLittleEndian(P.Y, 32)
	buf[31] |= byte(P.X.Bit(0)) << 7
	return buf
}

func DecodePoint(data []byte) (Point, error) {
	if len(data) != 32 {
		return Point{}, errors.New("bad point length")
	}

	yBytes := make([]byte, 32)
	copy(yBytes, data)
	yBytes[31] &= 127
	xSign := uint(data[31] >> 7)

	y := fromLittleEndian(yBytes)
	if y.Cmp(p) >= 0 {
		return Point{}, errors.New("y out of range")
	}

	one := big.NewInt(1)
	y2 := modMul(y, y)
	u := modSub(y2, one)
	v := modAdd(modMul(d, y2), one)

	v3 := modMul(modMul(v, v), v)
	v7 := modMul(modMul(v3, v3), v)
	uMulV3 := modMul(u, v3)
	uMulV7 := modMul(u, v7)

	exp := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(5)), big.NewInt(8))
	x := modMul(uMulV3, modExp(uMulV7, exp))

	vx2 := modMul(v, modMul(x, x))
	if vx2.Cmp(u) != 0 {
		if vx2.Cmp(modNeg(u)) != 0 {
			return Point{}, errors.New("point not on curve")
		}
		exp = new(big.Int).Div(new(big.Int).Sub(p, one), big.NewInt(4))
		x = modMul(x, modExp(big.NewInt(2), exp))
	}

	if x.Sign() == 0 && xSign == 1 {
		return Point{}, errors.New("invalid x sign")
	}
	if x.Bit(0) != xSign {
		x = modNeg(x)
	}

	return Point{X: x, Y: y}, nil
}
