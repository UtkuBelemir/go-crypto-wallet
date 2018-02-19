package main

import (
	"fmt"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	_"encoding/hex"

	"encoding/hex"
)
func pubKeysToAddress(pubPoint Point) (string){
	hasher := sha3.NewKeccak256()
	hasher.Reset()
	xHexVal := fmt.Sprintf("%x",pubPoint.cordX)
	yHexVal := fmt.Sprintf("%x",pubPoint.cordY)
	allHex := xHexVal+yHexVal
	tt,_ :=hex.DecodeString(allHex)
	hasher.Write(tt)
	summ := hasher.Sum(nil)
	encdd := hex.EncodeToString(summ)
	lastAddr := encdd[24:]
	return "0x"+lastAddr
}