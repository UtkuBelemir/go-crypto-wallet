package main

import (
	"fmt"
	"strings"
	"encoding/hex"
	"crypto/sha256"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/rand"
	"github.com/btcsuite/btcutil/base58"
	//Needed for generatingRandom number. Can be changed.
	mrand "math/rand"
	"time"
	"log"
	/*qrterminal.GenerateHalfBlock(privKey, qrterminal.L, os.Stdout)
	"github.com/mdp/qrterminal"
	"os"*/
	"math/big"
	"golang.org/x/crypto/ripemd160"
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
var cc Curve
func initCurve() Curve{
	tP,_ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671663",10)
	tN,_ := new(big.Int).SetString("115792089237316195423570985008687907852837564279074904382605163141518161494337",10)
	tA,_ := new(big.Int).SetString("0",10)
	tB,_ := new(big.Int).SetString("7",10)
	tGx,_ := new(big.Int).SetString("55066263022277343669578718895168534326250603453777594175500187360389116729240",10)
	tGy,_ := new(big.Int).SetString("32670510020758816978083085130507043184471273380659243275938904335757337482424",10)
	return Curve{ P:tP,N:tN,A:tA,B:tB,Gx:tGx,Gy:tGy,GPoint:Point{cordX:tGx,cordY:tGy}}
}
func init(){
	cc = initCurve()
}
const (
	BITCOINMAINNET  = "80"
	BITCOINTESTNET  = "EF"
	BYTECOINMAINNET = "92"
	BYTECOINTESTNET = "80"
	LITECOINMAINNET = "B0"
	LITECOINTESTNET = "EF"
	CHANGETHIS      = 10
)
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
	fmt.Println(privBinary)
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
func generatePublicKey(privKey string) string{
	publicKeyCoords := ECCMultiply(privKey[2:66])
	/*publicKeyCoords := ECCMultiply("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")*/
	fmt.Println("Public key x : ",publicKeyCoords.cordX," and y : ",publicKeyCoords.cordY)
	uncompressedPub := fmt.Sprintf("04%x%x",publicKeyCoords.cordX,publicKeyCoords.cordY)
	fmt.Println("Uncompressed Public Key : ",strings.ToUpper(uncompressedPub))
	var compressedPub string
	if new(big.Int).Mod(publicKeyCoords.cordY,big.NewInt(2)).Int64() == 1{
		compressedPub = strings.ToUpper(fmt.Sprintf("03%x",publicKeyCoords.cordX))
	}else{
		compressedPub = strings.ToUpper(fmt.Sprintf("02%x",publicKeyCoords.cordX))
	}
	fmt.Println("Compressed Public Key : ",compressedPub)
	unCompDecoded,_ := hex.DecodeString(uncompressedPub)
	sh1 := sha256.New()
	sh1.Reset()
	sh1.Write(unCompDecoded)
	shaSummer := sh1.Sum(nil)
	firstSHA256 := strings.ToUpper(hex.EncodeToString(shaSummer))
	fmt.Println("First SHA256",firstSHA256)
	rp1 := ripemd160.New()
	rp1.Write(shaSummer)
	firstRIPEMD160 := "00" + strings.ToUpper(hex.EncodeToString(rp1.Sum(nil)))
	fmt.Println("First RIPEMDN",firstRIPEMD160)
	rpDecoded,_:=hex.DecodeString(firstRIPEMD160)
	sh1.Reset()
	sh1.Write(rpDecoded)
	secondSHA256 := sh1.Sum(nil)
	sh1.Reset()
	sh1.Write(secondSHA256)
	thirdSHA256 := strings.ToUpper(hex.EncodeToString(sh1.Sum(nil)))
	latest:=firstRIPEMD160 + thirdSHA256[:8]
	hh,err := hex.DecodeString(latest)
	fmt.Println("Pub latest : ",latest)
	fmt.Println("Pub h : ",hh)
	fmt.Println("Pub err : ",err)
	publicAddr := base58.Encode(hh)
	return publicAddr
}
func main() {
	/*start := time.Now()
	defer printTime(start)*/
	privKey, privAddress := generatePrivateAddress(BITCOINMAINNET)
	fmt.Println(privKey[2:66])
	pubAddress := generatePublicKey(privKey)
	fmt.Println("PRIV KEY ",privAddress)
	fmt.Println("PUB KEY ",pubAddress)
	//48845523729413061808628158112419206155003300861119110225211913843344687359293
	//	fmt.Println(bgIn.ModInverse(big.NewInt(27),big.NewInt(392)))



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
func generatePrivateAddress(addrPrefix string) (string, string) {
	secretKey := generateRandom()
	firstKey := strings.ToUpper(hex.EncodeToString(secretKey))
	firstKey = addrPrefix + firstKey
	/*firstKey := "806BFD963281C2718E91DB424A61C38223286843F9C5CE71883FA90C560C7DE53D"*/
	firstKeyDecoded, _ := hex.DecodeString(firstKey)
	sh1 := sha256.New()
	sh1.Reset()
	sh1.Write(firstKeyDecoded)
	firstSHA256 := strings.ToUpper(hex.EncodeToString(sh1.Sum(nil)))
	sh1.Reset()
	firstHasDecoded, _ := hex.DecodeString(firstSHA256)
	sh1.Write(firstHasDecoded)
	secondSHA256 := strings.ToUpper(hex.EncodeToString(sh1.Sum(nil)))
	checksum := secondSHA256[:8]
	firstKey = firstKey + checksum
	fmt.Println("FİRİRİRİRİRİRİRİRİRİ : ",firstKey)
	hh, _ := hex.DecodeString(firstKey)
	fmt.Println("HHHHHH : ",hh)
	privateAdress := base58.Encode(hh)
	return firstKey, privateAdress

}
func printTime(start time.Time) {
	elapsed := time.Since(start)
	log.Printf("EXECUTED IN %s", elapsed)
}