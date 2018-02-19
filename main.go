package main

import "fmt"

func main(){
	/*start := time.Now()
	defer printTime(start)*/
	privKey, privAddress := generatePrivateAddress(BITCOINMAINNET)
	fmt.Println("PRIV HASH",privKey[2:66])
	pubPoint,pubAddress := generatePublicKey(privKey)
	fmt.Println("PRIV KEY ",privAddress)
	fmt.Println("PUB KEY ",pubAddress)
	fmt.Println(pubKeysToAddress(pubPoint))
}