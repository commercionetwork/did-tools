package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/btcec"
	id "github.com/commercionetwork/commercionetwork/x/id/types"
	"github.com/commercionetwork/sacco.go"
	"github.com/commercionetwork/sacco.go/softwarewallet"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/types"
	"github.com/tendermint/tendermint/crypto"
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

//func cli() (mnemonic, bech32pubkey, endpoint string) {
func cli() (mnemonic, endpoint string) {
	flag.StringVar(&mnemonic, "mnemonic", "", "mnemonic string")
	//flag.StringVar(&bech32pubkey, "pubkey", "", "bech32 pubkey")
	flag.StringVar(&endpoint, "vcaendpoint", "http://localhost:9091", "vca endpoint")
	flag.Parse()

	return
}

func main() {
	//mnemonic, bech32pubkey, end := cli()
	mnemonic, end := cli()
	sw, err := softwarewallet.Derive(softwarewallet.DeriveOptions{
		Path:     sacco.CosmosDerivationPath,
		HRP:      "did:com:",
		Mnemonic: mnemonic,
	})

	if err != nil {
		log.Fatal(err)
	}

	wallet, err := sacco.NewWallet(sw)
	if err != nil {
		log.Fatal(err)
	}

	config()
	bech32pubkey := wallet.PublicKey
	pubkey, err := types.GetPubKeyFromBech32(types.Bech32PubKeyTypeAccPub, bech32pubkey)
	if err != nil {
		log.Fatal(err)
	}

	_, _ = wallet, pubkey

	wacc, err := types.AccAddressFromBech32(wallet.Address)

	if err != nil {
		log.Fatal(err)
	}

	u := id.DidDocument{
		Context: "https://www.w3.org/ns/did/v1",
		ID:      wacc,
		PubKeys: id.PubKeys{
			id.PubKey{
				ID:           wallet.Address + "#keys-1",
				Type:         "RsaVerificationKey2018",
				Controller:   wacc,
				PublicKeyPem: verificationKey,
			},
			id.PubKey{
				ID:           wallet.Address + "#keys-2",
				Type:         "RsaSignatureKey2018",
				Controller:   wacc,
				PublicKeyPem: signingKey,
			},
			id.PubKey{
				ID:           wallet.Address + "#keys-3",
				Type:         "Secp256k1VerificationKey2018",
				Controller:   wacc,
				PublicKeyPem: hex.EncodeToString([]byte("new key!")),
			},
		},
		Service: id.Services{
			id.Service{
				ID:              "ssi service endpoint",
				Type:            "ssi",
				ServiceEndpoint: end,
			},
		},
	}

	//var testZone, _ = time.LoadLocation("UTC")
	//var testTime = time.Date(2016, 2, 8, 16, 2, 20, 0, testZone)

	oProof := id.Proof{
		Type:               "EcdsaSecp256k1VerificationKey2019",
		Created:            time.Now(),
		ProofPurpose:       "authentication",
		Controller:         u.ID.String(),
		VerificationMethod: bech32pubkey,
	}

	data, err := json.Marshal(u)
	if err != nil {
		log.Fatal(err)
	}

	signature, err := sw.SignBlob(crypto.Sha256(data[:]))
	if err != nil {
		log.Fatal(err)
	}

	bs := &btcec.Signature{
		R: big.NewInt(0).SetBytes(signature.R),
		S: big.NewInt(0).SetBytes(signature.S),
	}

	oProof.SignatureValue = base64.StdEncoding.EncodeToString(serializeSig(bs))

	u.Proof = &oProof

	tx := associateTx(u)

	cdc := codec.New()
	j, err := cdc.MarshalJSON(tx)
	if err != nil {
		log.Fatal(err)
	}

	if err := u.Validate(); err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(j))

	signAndSend(wallet, []json.RawMessage{j})
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
	Type  string         `json:"type"`
	Value id.DidDocument `json:"value"`
}

func associateTx(didoc id.DidDocument) atx {
	return atx{
		Type:  "commercio/MsgSetIdentity",
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
