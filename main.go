package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls/common"
)

func main() {

	var (
		xMsgs      [][32]byte
		xSigsBytes [][]byte
		sigs       []common.Signature
		xPKs       []common.PublicKey
	)

	sk, err := bls.RandKey()
	if err != nil {
		fmt.Println(err)
		return
	}

	for i := range 10 {
		var msg [32]byte
		copy(msg[:], fmt.Sprintf("Hello BLS %v", i))
		xMsgs = append(xMsgs, msg) // add to xMsgs

		data := make([]byte, 32)
		copy(data[:], msg[:])

		sigs = append(sigs, sk.Sign(data))
	}

	agg := bls.AggregateSignatures(sigs)
	aggHex := hexutil.Encode(agg.Marshal())
	fmt.Println("aggregated sig:", aggHex)

	msg := [32]byte{}
	copy(msg[:], "Hello BLS 0")
	fmt.Println("outer msg:", msg)

	s, err := bls.VerifySignature(sigs[0].Marshal(), msg, sk.PublicKey())
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Verification result for one sig:", s)

	for _, sig := range sigs {
		xSigsBytes = append(xSigsBytes, sig.Marshal())
		xPKs = append(xPKs, sk.PublicKey())
	}

	s, err = bls.VerifyMultipleSignatures(xSigsBytes, xMsgs, xPKs)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println("Verification result for multiple sig:", s)
}
