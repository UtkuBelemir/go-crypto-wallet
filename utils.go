package main

import (
	"math/big"
	"fmt"
	"time"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/rand"
	mrand "math/rand"
	"log"
)

type Point struct{
	cordX *big.Int
	cordY *big.Int
}
type Curve struct{
	P *big.Int
	N *big.Int
	A *big.Int
	B *big.Int
	Gx *big.Int
	Gy *big.Int
	GPoint Point
}

func initCurve() Curve{
	tP,_ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663",10)
	tN,_ := new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337",10)
	tA,_ := new(big.Int).SetString("0",10)
	tB,_ := new(big.Int).SetString("7",10)
	tGx,_ := new(big.Int).SetString("55066263022277343669578718895168534326250603453777594175500187360389116729240",10)
	tGy,_ := new(big.Int).SetString("32670510020758816978083085130507043184471273380659243275938904335757337482424",10)
	return Curve{ P:tP,N:tN,A:tA,B:tB,Gx:tGx,Gy:tGy,GPoint:Point{cordX:tGx,cordY:tGy}}
}
func ECCAdd(tPoint Point) Point{
	yLeriCikar := new(big.Int).Sub(cc.GPoint.cordY,tPoint.cordY)
	xLeriCikar := new(big.Int).Sub(cc.GPoint.cordX,tPoint.cordX)
	tersMod := new(big.Int).ModInverse(xLeriCikar,cc.P)
	tersModCarpiYFark := new(big.Int).Mul(yLeriCikar,tersMod)
	hepsininModu := new(big.Int).Mod(tersModCarpiYFark,cc.P)
	LambdaAdd := hepsininModu
	LambdaAddKare := new(big.Int).Mul(LambdaAdd,LambdaAdd)
	LKareEksiIlkX := new(big.Int).Sub(LambdaAddKare,tPoint.cordX)
	LKareSonEksiIkinciX := new(big.Int).Sub(LKareEksiIlkX,cc.GPoint.cordX)
	yeniX := new(big.Int).Mod(LKareSonEksiIkinciX,cc.P)
	ilkXEksiYeniX := new(big.Int).Sub(tPoint.cordX,yeniX)
	LambdaCarpiSonX := new(big.Int).Mul(LambdaAdd,ilkXEksiYeniX)
	LambdaCarpiSonXEksiIlkY := new(big.Int).Sub(LambdaCarpiSonX,tPoint.cordY)
	yeniY := new(big.Int).Mod(LambdaCarpiSonXEksiIlkY,cc.P)
	return Point{ cordX:yeniX,cordY:yeniY}
}
func ECCDouble(tPoint Point) Point{
	ilkXKareler := new(big.Int).Mul(tPoint.cordX,tPoint.cordX)
	karelerCarpiUc := new(big.Int).Mul(big.NewInt(3),ilkXKareler)
	carpimlarArtiCURVEA := new(big.Int).Add(karelerCarpiUc,cc.A)
	ikiCarpiIlkY := new(big.Int).Mul(big.NewInt(2),tPoint.cordY)
	tersMod := new(big.Int).ModInverse(ikiCarpiIlkY,cc.P)
	sonCarpim := new(big.Int).Mul(carpimlarArtiCURVEA,tersMod)
	LambdaDouble := new(big.Int).Mod(sonCarpim,cc.P)
	LambdaDoubleKare := new(big.Int).Mul(LambdaDouble,LambdaDouble)
	ikiCaripIlkX := new(big.Int).Mul(big.NewInt(2),tPoint.cordX)
	LKareEksiIlkX := new(big.Int).Sub(LambdaDoubleKare,ikiCaripIlkX)
	yeniX := new(big.Int).Mod(LKareEksiIlkX,cc.P)
	ilkXEksiYeniX := new(big.Int).Sub(tPoint.cordX,yeniX)
	LambdaCarpiSonX := new(big.Int).Mul(LambdaDouble,ilkXEksiYeniX)
	LambdaCarpiSonXEksiIlkY := new(big.Int).Sub(LambdaCarpiSonX,tPoint.cordY)
	yeniY := new(big.Int).Mod(LambdaCarpiSonXEksiIlkY,cc.P)
	return Point{ cordX:yeniX,cordY:yeniY}
}
func ECCMultiply(privateKeyHex string) Point{
	privKeyForBin,_ := new(big.Int).SetString(privateKeyHex,16)

	privBinary := fmt.Sprintf("%b",privKeyForBin)
	//fmt.Println(privBinary)
	//USE 49 for "1" and USE 48 for "0"
	Q := cc.GPoint
	for i :=1;i<len(privBinary);i++{
		Q = ECCDouble(Q)
		if privBinary[i] == 49{
			Q = ECCAdd(Q)
		}
	}
	return Q
}
func generateRandom() ([]byte) {
	randomSeed := make([]byte, 256)
	rand.Read(randomSeed)
	mrand.Seed(time.Now().UnixNano())
	i := mrand.Int31() % CHANGETHIS
	x1 := hmac.New(sha512.New, randomSeed)
	x1.Write(randomSeed)
	for ; i > 0; i-- {
		x1 = hmac.New(sha512.New, x1.Sum(nil))
		x1.Write(x1.Sum(nil))
	}
	returnVal := x1.Sum(nil)
	return returnVal[:len(returnVal)/2]
}
func printTime(start time.Time) {
	elapsed := time.Since(start)
	log.Printf("EXECUTED IN %s", elapsed)
}