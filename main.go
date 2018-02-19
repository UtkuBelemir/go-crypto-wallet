package main

import (
	"fmt"
	"strings"
)

func main(){
	/*start := time.Now()
	defer printTime(start)*/
	privKey, privAddress := generatePrivateAddress(BITCOINMAINNET_PRIV)

	pubPoint,pubAddress := generatePublicKey(privKey,BITCOINTESTNET_PUB)
	ethPub := pubKeysToAddress(pubPoint)
	ethPriv := strings.ToLower(privKey[2:66])
	fmt.Println("BITCOIN PRIVATE ADDRESS : ",privAddress," AND BITCOIN PUBLIC ADDRESS : ",pubAddress)
	fmt.Println("ETHEREUM PRIVATE ADDRESS : ","0x"+ethPriv," AND ETHEREUM PUBLIC ADDRESS : ",ethPub)
}