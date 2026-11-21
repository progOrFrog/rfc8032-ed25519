package ed25519

import "math/big"

type Point struct {
	X *big.Int
	Y *big.Int
}

func Identity() Point {
	return Point{X: new(big.Int).Set(identityX), Y: new(big.Int).Set(identityY)}
}

func BasePoint() Point {
	return Point{X: new(big.Int).Set(baseX), Y: new(big.Int).Set(baseY)}
}

func PointAdd(P, Q Point) Point {
	x1y2 := modMul(P.X, Q.Y)
	y1x2 := modMul(P.Y, Q.X)
	y1y2 := modMul(P.Y, Q.Y)
	x1x2 := modMul(P.X, Q.X)

	one := big.NewInt(1)
	dx1x2y1y2 := modMul(d, modMul(x1x2, y1y2))

	x3 := modMul(modAdd(x1y2, y1x2), modInv(modAdd(one, dx1x2y1y2)))
	y3 := modMul(modAdd(y1y2, x1x2), modInv(modSub(one, dx1x2y1y2)))

	return Point{X: x3, Y: y3}
}

func ScalarMult(k *big.Int, P Point) Point {
	result := Identity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		result = PointAdd(result, result)
		if k.Bit(i) == 1 {
			result = PointAdd(result, P)
		}
	}
	return result
}
