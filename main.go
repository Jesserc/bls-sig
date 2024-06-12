package main

import (
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls/common"
)

var (
	ErrInvalidMsgLength = errors.New("error: message must be less than 32 bytes")
)

// GenerateKeyPair creates a new BLS key pair and returns the secret key and public key as hex-encoded strings
func GenerateKeyPair() (string, string, error) {
	sk, err := bls.RandKey()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate key pair: %v", err)
	}

	return hexutil.Encode(sk.Marshal()), hexutil.Encode(sk.PublicKey().Marshal()), nil
}

// GenerateSignature creates a BLS signature for a given message using the provided hex-encoded secret key
func GenerateSignature(privKeyHex, msg string) (string, error) {
	skBytes, err := hexutil.Decode(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret key hex to bytes: %v", err)
	}
	sk, err := bls.SecretKeyFromBytes(skBytes)
	if err != nil {
		return "", fmt.Errorf("failed to convert secret key hex to common.SecretKey: %v", err)
	}

	var msgBytes [32]byte
	copy(msgBytes[:], msg)
	sig := sk.Sign(msgBytes[:])
	return hexutil.Encode(sig.Marshal()), nil
}

// AggregateSignatures combines multiple BLS signatures into a single aggregate signature
func AggregateSignatures(sigHexes []string) (string, error) {
	sigs := make([]common.Signature, 0, len(sigHexes))

	for _, sigHex := range sigHexes {
		sigBytes, err := hexutil.Decode(sigHex)
		if err != nil {
			return "", fmt.Errorf("failed to decode signature hex to bytes: %v", err)
		}

		sig, err := bls.SignatureFromBytes(sigBytes)
		if err != nil {
			return "", fmt.Errorf("failed to convert signature bytes to common.Signature: %v", err)
		}
		sigs = append(sigs, sig)
	}

	aggSig := bls.AggregateSignatures(sigs)
	return hexutil.Encode(aggSig.Marshal()), nil
}

// VerifySignature checks if a given BLS signature is valid for a message using the provided hex-encoded public key
func VerifySignature(pubKeyHex, sigHex, msg string) (bool, error) {
	if len([]byte(msg)) > 32 {
		return false, ErrInvalidMsgLength
	}

	sigBytes, err := hexutil.Decode(sigHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode signature hex to bytes: %v", err)
	}

	pubKeyBytes, err := hexutil.Decode(pubKeyHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode public key hex to bytes: %v", err)
	}

	pubKey, err := bls.PublicKeyFromBytes(pubKeyBytes)
	if err != nil {
		return false, fmt.Errorf("failed to convert public key bytes to common.PublicKey: %v", err)
	}

	var msgBytes [32]byte
	copy(msgBytes[:], msg)
	return bls.VerifySignature(sigBytes, msgBytes, pubKey)
}

func VerifyAggregateSignature(aggregateSigHex, msg string, pubKeyHexes []string) (bool, error) {
	// (sigs [][]byte, msgs [][32]byte, pubKeys []common.PublicKey)
	var (
		xSigsBytes = make([][]byte, 0, len(pubKeyHexes))
		xMsgs      = make([][32]byte, 0, len(pubKeyHexes))
		xPKs       = make([]common.PublicKey, 0, len(pubKeyHexes))

		sigs = make([]common.Signature, 0, len(pubKeyHexes))
	)

	for _, pubKeyHex := range pubKeyHexes {
		var msgBytes [32]byte
		copy(msgBytes[:], msg)
		xMsgs = append(xMsgs, msgBytes)

		pubKeyBytes, err := hexutil.Decode(pubKeyHex)
		if err != nil {
			return false, fmt.Errorf("failed to decode public key hex to bytes: %v", err)
		}

		pubKey, err := bls.PublicKeyFromBytes(pubKeyBytes)
		if err != nil {
			return false, fmt.Errorf("failed to convert public key bytes to common.PublicKey: %v", err)
		}
		xPKs = append(xPKs, pubKey)

		sigBytes, err := hexutil.Decode(aggregateSigHex)
		if err != nil {
			return false, fmt.Errorf("failed to decode signature hex to bytes: %v", err)
		}

		sig, err := bls.SignatureFromBytes(sigBytes)
		if err != nil {
			return false, fmt.Errorf("failed to convert signature bytes to common.Signature: %v", err)
		}
		sigs = append(sigs, sig)
	}

	for _, sig := range sigs {
		xSigsBytes = append(xSigsBytes, sig.Marshal())
	}
	// (sigs [][]byte, msgs [][32]byte, pubKeys []common.PublicKey)
	return bls.VerifyMultipleSignatures(xSigsBytes, xMsgs, xPKs)
}

func main() {
	privKey, pubKey, err := GenerateKeyPair()
	if err != nil {
		fmt.Println("Error generating key pair:", err)
		return
	}
	fmt.Println("Private Key:", privKey)
	fmt.Println("Public Key:", pubKey)

	message := "test message"
	signature, err := GenerateSignature(privKey, message)
	if err != nil {
		fmt.Println("Error generating signature:", err)
		return
	}
	fmt.Println("Signature:", signature)

	valid, err := VerifySignature(pubKey, signature, message)
	if err != nil {
		fmt.Println("Error verifying signature:", err)
		return
	}
	fmt.Println("Signature valid:", valid)

	pubKeyHexes := make([]string, 0, 5)
	sigHexes := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		pubKeyHexes = append(pubKeyHexes, pubKey)
		sigHexes = append(sigHexes, signature)
	}

	aggSig, err := AggregateSignatures(sigHexes)
	if err != nil {
		fmt.Println("Error aggregating signatures:", err)
		return
	}
	fmt.Println("Aggregate Signature:", aggSig)

	valid, err = VerifyAggregateSignature(aggSig, message, pubKeyHexes)
	if err != nil {
		fmt.Println("Error verifying aggregate signature:", err)
		return
	}
	fmt.Println("Aggregate signature valid:", valid)
}
