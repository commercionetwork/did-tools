package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"strconv"
	"time"

	uuid "github.com/satori/go.uuid"

	"github.com/cosmos/cosmos-sdk/codec"

	"github.com/btcsuite/btcd/btcec"
	"github.com/commercionetwork/commercionetwork/x/id"
	"github.com/commercionetwork/sacco.go"
	"github.com/cosmos/cosmos-sdk/types"
)

var (
	// Bech32PrefixAccAddr defines the Bech32 prefix of an account's address
	Bech32MainPrefix = "did:com:"

	// PrefixValidator is the prefix for validator keys
	PrefixValidator = "val"
	// PrefixConsensus is the prefix for consensus keys
	PrefixConsensus = "cons"
	// PrefixPublic is the prefix for public keys
	PrefixPublic = "pub"
	// PrefixOperator is the prefix for operator keys
	PrefixOperator = "oper"

	// Bech32PrefixAccAddr defines the Bech32 prefix of an account's address
	Bech32PrefixAccAddr = Bech32MainPrefix
	// Bech32PrefixAccPub defines the Bech32 prefix of an account's public key
	Bech32PrefixAccPub = Bech32MainPrefix + PrefixPublic
	// Bech32PrefixValAddr defines the Bech32 prefix of a validator's operator address
	Bech32PrefixValAddr = Bech32MainPrefix + PrefixValidator + PrefixOperator
	// Bech32PrefixValPub defines the Bech32 prefix of a validator's operator public key
	Bech32PrefixValPub = Bech32MainPrefix + PrefixValidator + PrefixOperator + PrefixPublic
	// Bech32PrefixConsAddr defines the Bech32 prefix of a consensus node address
	Bech32PrefixConsAddr = Bech32MainPrefix + PrefixValidator + PrefixConsensus
	// Bech32PrefixConsPub defines the Bech32 prefix of a consensus node public key
	Bech32PrefixConsPub = Bech32MainPrefix + PrefixValidator + PrefixConsensus + PrefixPublic

	lcd = "http://localhost:1317"
)

// didDocumentUnsigned is an intermediate type used to check for proof correctness
type didDocumentUnsigned struct {
	Context string           `json:"@context"`
	ID      types.AccAddress `json:"id"`
	PubKeys id.PubKeys       `json:"publicKey"`
}

func main() {
	mnemonic := "rice chimney person copper pact lamp rubber name cup violin power float super stairs zebra nasty result aware solution awkward shock outside pupil toward"
	wallet, err := sacco.FromMnemonic("did:com:", mnemonic, sacco.CosmosDerivationPath)
	if err != nil {
		log.Fatal(err)
	}

	config()

	pairwise, err := types.AccAddressFromBech32("did:com:15jv74vsdk23pvvf2a8arex339505mgjytz98xc")
	if err != nil {
		log.Fatal(err)
	}

	wacc, err := types.AccAddressFromBech32(wallet.Address)
	if err != nil {
		log.Fatal(err)
	}

	request := id.MsgRequestDidPowerUp{
		Claimant: wacc,
		Amount: types.Coins{types.Coin{
			Denom:  "ucommercio",
			Amount: types.NewInt(100),
		}},
		ID: uuid.NewV4().String(),
	}

	// build proof for request
	proof := requestPowerupProof{
		SenderDid:   wacc,
		PairwiseDid: pairwise,
		Timestamp:   time.Now().Unix(),
	}

	sigPayload := proof.SenderDid.String() + proof.PairwiseDid.String() + strconv.FormatInt(proof.Timestamp, 10)
	payloadHash := sha256.Sum256([]byte(sigPayload))

	// parse the rsa private key
	privPem, _ := pem.Decode([]byte(signingPrivKey))
	rsaPrivRaw, err := x509.ParsePKCS8PrivateKey(privPem.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	rsaPriv, ok := rsaPrivRaw.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("could not cast to private key")
	}
	// sign the proof hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaPriv, crypto.SHA256, payloadHash[:])
	if err != nil {
		log.Fatal(err)
	}

	// encode in base64
	proof.Signature = base64.StdEncoding.EncodeToString(signature)

	// encode to json
	cdc := codec.New()
	proofJSON, _ := cdc.MarshalJSON(proof)

	/*
		proof now contains the blob we will encrypt with the tumbler public key
	*/

	tumblerPemDec, _ := pem.Decode([]byte(tumblerPubkey))
	tumblerKeyRaw, err := x509.ParsePKIXPublicKey([]byte(tumblerPemDec.Bytes))
	if err != nil {
		log.Fatal(err)
	}

	tumblerKey := tumblerKeyRaw.(*rsa.PublicKey)

	// AES-GCM encryption of proofJSON
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, proofJSON, nil)

	finalc := bytes.Buffer{}
	finalc.Write(nonce)
	finalc.Write(ciphertext)

	// convert it in base64
	epb64 := base64.StdEncoding.EncodeToString(finalc.Bytes())

	_ = epb64
	request.Proof = epb64

	encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, tumblerKey, key)
	if err != nil {
		log.Fatal(err)
	}

	// convert it in base64
	keyb64 := base64.StdEncoding.EncodeToString(encryptedKey)
	_ = keyb64

	request.ProofKey = keyb64

	tx := associateTx(request)

	j, err := cdc.MarshalJSON(tx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(j))

	//signAndSend(wallet, []json.RawMessage{j})

}

/*
{
	"sender_did":	"[Did mittente]"
	"pairwise_did": "[Did di cui fare il PowerUp]",
	"timestamp": 	"[data/ora in formato UNIX]",
	"signature": 	"[K]"
}

*/

type requestPowerupProof struct {
	SenderDid   types.AccAddress `json:"sender_did"`
	PairwiseDid types.AccAddress `json:"pairwise_did"`
	Timestamp   int64            `json:"timestamp"`
	Signature   string           `json:"signature"`
}

type requestPowerupUnsigned struct {
	Claimant types.AccAddress `json:"claimant"`
	Amount   types.Coins      `json:"amount"`
}

func config() {
	config := types.GetConfig()
	config.SetBech32PrefixForAccount(Bech32PrefixAccAddr, Bech32PrefixAccPub)
	config.SetBech32PrefixForValidator(Bech32PrefixValAddr, Bech32PrefixValPub)
	config.SetBech32PrefixForConsensusNode(Bech32PrefixConsAddr, Bech32PrefixConsPub)
	config.Seal()
}

func serializeSig(sig *btcec.Signature) []byte {
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	sigBytes := make([]byte, 64)
	// 0 pad the byte arrays from the left if they aren't big enough.
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	return sigBytes
}

type atx struct {
	Type  string                  `json:"type"`
	Value id.MsgRequestDidPowerUp `json:"value"`
}

func associateTx(didoc id.MsgRequestDidPowerUp) atx {
	return atx{
		Type:  "commercio/MsgRequestDidPowerUp",
		Value: didoc,
	}
}

func genTx(msg []json.RawMessage) sacco.TransactionPayload {
	fee := sacco.Fee{
		Amount: sacco.Coins{
			sacco.Coin{
				Denom:  "ucommercio",
				Amount: "10000",
			},
		},
		Gas: "200000",
	}

	tp := sacco.TransactionPayload{
		Message: msg,
		Fee:     fee,
	}

	return tp
}

func signAndSend(wallet *sacco.Wallet, rawMsg []json.RawMessage) {
	mode := sacco.ModeBlock

	txHash, err := wallet.SignAndBroadcast(genTx(rawMsg), lcd, mode)
	if err != nil {
		log.Fatal(err)
		return
	}

	fmt.Println("sent, hash:", txHash)
}

func transformJSON(r interface{}) ([]byte, error) {
	data, err := json.Marshal(r)
	if err != nil {
		// something went absolutely wrong, do not marshal an error, just return a generic error string and
		// log
		err = fmt.Errorf("could not marshal JSON response: %w", err)

		return nil, err
	}

	return data, nil
}
