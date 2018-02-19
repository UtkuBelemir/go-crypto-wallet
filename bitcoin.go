package main

import (
	"fmt"
	"strings"
	"encoding/hex"
	"crypto/sha256"
	"github.com/btcsuite/btcutil/base58"

	/*qrterminal.GenerateHalfBlock(privKey, qrterminal.L, os.Stdout)
	"github.com/mdp/qrterminal"
	"os"*/
//	"math/big"
	"golang.org/x/crypto/ripemd160"
)

var cc Curve
func init(){
	cc = initCurve()
}
type BTCWallet struct{

}
func generatePublicKey(privKey string) (Point,string){
	publicKeyCoords := ECCMultiply(privKey[2:66])
	/*publicKeyCoords := ECCMultiply("18E14A7B6A307F426A94F8114701E7C8E774E7F9A47E2C2035DB29A206321725")*/
	//fmt.Println("Public key x : ",publicKeyCoords.cordX," and y : ",publicKeyCoords.cordY)
	uncompressedPub := fmt.Sprintf("04%x%x",publicKeyCoords.cordX,publicKeyCoords.cordY)
	fmt.Println("Uncompressed Public Key : ",strings.ToUpper(uncompressedPub))
	fmt.Printf("uncomp x : %x and y : %x\n",publicKeyCoords.cordX,publicKeyCoords.cordY)
	/*var compressedPub string
	if new(big.Int).Mod(publicKeyCoords.cordY,big.NewInt(2)).Int64() == 1{
		compressedPub = strings.ToUpper(fmt.Sprintf("03%x",publicKeyCoords.cordX))
	}else{
		compressedPub = strings.ToUpper(fmt.Sprintf("02%x",publicKeyCoords.cordX))
	}
	fmt.Println("Compressed Public Key : ",compressedPub)*/
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
	//fmt.Println("First RIPEMDN",firstRIPEMD160)
	rpDecoded,_:=hex.DecodeString(firstRIPEMD160)
	sh1.Reset()
	sh1.Write(rpDecoded)
	secondSHA256 := sh1.Sum(nil)
	sh1.Reset()
	sh1.Write(secondSHA256)
	thirdSHA256 := strings.ToUpper(hex.EncodeToString(sh1.Sum(nil)))
	latest:=firstRIPEMD160 + thirdSHA256[:8]
	hh,_ := hex.DecodeString(latest)
	fmt.Println("Pub latest : ",latest)
	fmt.Println("Pub h : ",hh)
	publicAddr := base58.Encode(hh)
	return publicKeyCoords,publicAddr
}
func generatePrivateAddress(addrPrefix string) (string, string) {
	/*secretKey := generateRandom()
	firstKey := strings.ToUpper(hex.EncodeToString(secretKey))
	firstKey = addrPrefix + firstKey*/
	firstKey := "91b3bdcfebb84a9bf7a3719cd855256067831888958aa102553356d1d6a816f9"
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
	//fmt.Println("FİRİRİRİRİRİRİRİRİRİ : ",firstKey)
	hh, _ := hex.DecodeString(firstKey)
	//fmt.Println("HHHHHH : ",hh)
	privateAdress := base58.Encode(hh)
	return firstKey, privateAdress
}