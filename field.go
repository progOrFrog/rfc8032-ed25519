package ed25519

import "math/big"

var (
	p = new(big.Int).Sub(powerOfTwo(255), big.NewInt(19))

	d = modMul(modNeg(big.NewInt(121665)), modInv(big.NewInt(121666)))

	L = new(big.Int).Add(powerOfTwo(252), parseBigInt("27742317777372353535851937790883648493"))

	identityX = big.NewInt(0)
	identityY = big.NewInt(1)

	baseY = modMul(big.NewInt(4), modInv(big.NewInt(5)))
	baseX = parseBigInt("15112221349535400772501151409588531511454012693041857206046113283949847762202")
)

func powerOfTwo(exponent uint) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), exponent)
}

func parseBigInt(decimal string) *big.Int {
	n, ok := new(big.Int).SetString(decimal, 10)
	if !ok {
		panic("invalid decimal constant")
	}
	return n
}

func modAdd(a, b *big.Int) *big.Int {
	result := new(big.Int).Add(a, b)
	return result.Mod(result, p)
}

func modSub(a, b *big.Int) *big.Int {
	result := new(big.Int).Sub(a, b)
	return result.Mod(result, p)
}

func modNeg(a *big.Int) *big.Int {
	result := new(big.Int).Neg(a)
	return result.Mod(result, p)
}

func modMul(a, b *big.Int) *big.Int {
	result := new(big.Int).Mul(a, b)
	return result.Mod(result, p)
}

func modInv(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, p)
}

func modExp(base, exponent *big.Int) *big.Int {
	return new(big.Int).Exp(base, exponent, p)
}
