package main

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/satori/go.uuid"

	"github.com/ant0ine/go-json-rest/rest"
)

type Blockchain struct {
	Chain               []Block
	CurrentTransactions []Transaction
}

type Transaction struct {
	Sender    string
	Recipient string
	Amount    float64
}

type Block struct {
	Index        int
	Timestamp    int64
	Transactions []Transaction
	Proof        int
	PreviousHash string
}

// NewTransaction creates a new transaction to go into the next mind Block
// - sender: Address of the Sender
// - recipient: Address of the Recipient
// - amount: Amount
// return: The index of the Block that will hold this transcation
func (b *Blockchain) NewTransaction(sender string, recipient string, amount float64) int {
	b.CurrentTransactions = append(b.CurrentTransactions, Transaction{
		Sender:    sender,
		Recipient: recipient,
		Amount:    amount,
	})
	return b.lastBlock().Index + 1
}

// NewBlock creates a new block in the blockchain
// - proof: The proof given by the Proof of Work algorithm
// - previousHash: (Optional) <str> Hash of previous Block
// return: New Block
func (b *Blockchain) NewBlock(proof int, previousHash string) Block {
	block := Block{
		Index:        len(b.Chain) + 1,
		Timestamp:    time.Now().UTC().Unix(),
		Transactions: b.CurrentTransactions,
		Proof:        proof,
		PreviousHash: func() string {
			if previousHash != "" {
				return previousHash
			}
			return Hash(b.lastBlock())
		}(),
	}

	// Reset the current list of transcations
	b.CurrentTransactions = []Transaction{}
	b.Chain = append(b.Chain, block)
	return block
}

func (b *Blockchain) lastBlock() Block {
	return b.Chain[len(b.Chain)-1]
}

// ProofOfWork find a number p' such that hash(pp') contains leading 4 zeroes, where p is the previous p'
// p is the previous proof, p' is the new proof
// - lastProof: previous proof
// returns new proof
func (b *Blockchain) ProofOfWork(lastProof int) int {
	proof := 0
	for !ValidProof(lastProof, proof) {
		proof++
	}
	return proof
}

// ValidProof validates the proof Does hash(lastProof, proof) contains 4 leading zeroes?
// - lastProof: previous proof
// - proof: current proof
// returns True if correct, False if not
func ValidProof(lastProof, proof int) bool {
	guess := string(lastProof) + string(proof)
	guessHash := crypto.SHA256.New()
	guessHash.Write([]byte(guess))
	guessHex := hex.EncodeToString(guessHash.Sum(nil))
	return guessHex[:4] == "0000"
}

// Hash creates a SHA-256 hash of a Block
func Hash(block Block) string {
	blockByte, _ := json.Marshal(block)
	h := crypto.SHA256.New()
	h.Write(blockByte)
	hashByte := h.Sum(blockByte)
	return hex.EncodeToString(hashByte)
}

func NewBlockchain() *Blockchain {
	var blockChain = new(Blockchain)
	blockChain.Chain = []Block{}
	blockChain.CurrentTransactions = []Transaction{}
	blockChain.NewBlock(100, "1")
	return blockChain
}

var nodeIdentifier string

func main() {
	nodeIdentifier = strings.Replace(uuid.NewV4().String(), "-", "", -1)
	chainRest := NewBlockchainRest()
	chainRest.blockchain = NewBlockchain()

	api := rest.NewApi()
	api.Use(rest.DefaultDevStack...)
	router, err := rest.MakeRouter(
		rest.Get("/mine", chainRest.Mine),
		rest.Post("/transcations/new", chainRest.NewTransaction),
		rest.Get("/chain", chainRest.FullChain),
	)
	if err != nil {
		log.Fatal(err)
	}
	api.SetApp(router)
	log.Fatal(http.ListenAndServe(":8080", api.MakeHandler()))
}

type BlockchainRest struct {
	blockchain *Blockchain
}

func NewBlockchainRest() *BlockchainRest {
	chainRest := &BlockchainRest{}
	return chainRest
}

func (chainRest *BlockchainRest) Mine(w rest.ResponseWriter, r *rest.Request) {
	b := chainRest.blockchain
	// We run the poof of work algorithm to get the next proof
	lastBlock := b.lastBlock()
	lastProof := lastBlock.Proof
	proof := b.ProofOfWork(lastProof)

	// We must receive a reward for finding the proof
	// The sender is "0" to signify this node has mined a new coin
	b.NewTransaction("0", nodeIdentifier, 1)

	// Forge the new Block by adding it to the chain
	block := b.NewBlock(proof, "")
	fmt.Printf("%+v\n", block)

	w.WriteJson(&struct {
		Message      string
		Index        int
		Transcations []Transaction
		Proof        int
		PreviousHash string
	}{
		Message:      "New Block Forged",
		Index:        block.Index,
		Transcations: block.Transactions,
		Proof:        block.Proof,
		PreviousHash: block.PreviousHash,
	})
}

func (chainRest *BlockchainRest) NewTransaction(w rest.ResponseWriter, r *rest.Request) {
	b := chainRest.blockchain
	decodeTranc := Transaction{}
	err := r.DecodeJsonPayload(&decodeTranc)
	if err != nil {
		rest.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if decodeTranc.Amount == 0 || decodeTranc.Sender == "" || decodeTranc.Recipient == "" {
		rest.Error(w, "All model fields required", http.StatusBadRequest)
		return
	}
	index := b.NewTransaction(decodeTranc.Sender, decodeTranc.Recipient, decodeTranc.Amount)
	w.WriteJson(&struct {
		Message string
	}{
		Message: fmt.Sprintf("Transaction will be added to Block %d", index),
	})
}

func (chainRest *BlockchainRest) FullChain(w rest.ResponseWriter, r *rest.Request) {
	b := chainRest.blockchain
	response := struct {
		Chain []Block
		Len   int
	}{
		Chain: b.Chain,
		Len:   len(b.Chain),
	}
	w.WriteJson(&response)
}
