package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cryptoMimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"golang.org/x/crypto/argon2"
)

// --- Configuration ---
const (
	FeatureSize    = 60 // 30 Minutiae * 2 coordinates (x, y)
	FuzzyThreshold = 3  // Allowable difference in pixels
)

// --- Global ZKP State ---
var (
	ccs constraint.ConstraintSystem
	pk  groth16.ProvingKey
	vk  groth16.VerifyingKey
	// Metrics Cache
	nbConstraints int
	pkSize        int
	vkSize        int
)

// --- 1. Circuit Definition ---

type Circuit struct {
	Original [FeatureSize]frontend.Variable `gnark:"original,private"`
	Current  [FeatureSize]frontend.Variable `gnark:"current,private"`

	Password frontend.Variable `gnark:"password,private"`
	Salt     frontend.Variable `gnark:"salt,private"`

	// PUBLIC INPUTS
	Commitment     frontend.Variable `gnark:"commitment,public"`
	Challenge      frontend.Variable `gnark:"challenge,public"`
	BoundChallenge frontend.Variable `gnark:"bound_challenge,public"` // New binding constraint
}

func (c *Circuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// 1. Integrity Check (Commitment)
	for i := 0; i < FeatureSize; i++ {
		h.Write(c.Original[i])
	}
	h.Write(c.Password)
	h.Write(c.Salt)
	result := h.Sum()
	api.AssertIsEqual(c.Commitment, result)

	// 2. Nonce Binding
	// We hash the public Commitment and the public Challenge together.
	// This proves the current proof is bound to THIS commitment AND THIS nonce.
	h.Reset()
	h.Write(c.Commitment)
	h.Write(c.Challenge)
	bindingResult := h.Sum()
	api.AssertIsEqual(c.BoundChallenge, bindingResult)

	// 3. Fuzzy Logic
	thresholdSq := FuzzyThreshold * FuzzyThreshold
	for i := 0; i < FeatureSize; i++ {
		diff := api.Sub(c.Original[i], c.Current[i])
		distSq := api.Mul(diff, diff)
		api.AssertIsLessOrEqual(distSq, thresholdSq)
	}
	return nil
}

// --- 2. Initialization ---

func initZKP() {
	log.Println("--- [Setup] Initializing Groth16 Fuzzy ZKP System (BN254) ---")
	var circuit Circuit
	var err error
	ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("[Setup] Circuit compilation failed: %v", err)
	}
	pk, vk, err = groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("[Setup] Trusted Setup failed: %v", err)
	}

	// Capture Metrics
	nbConstraints = ccs.GetNbConstraints()

	var buf bytes.Buffer
	pk.WriteTo(&buf)
	pkSize = buf.Len()

	buf.Reset()
	vk.WriteTo(&buf)
	vkSize = buf.Len()

	log.Printf("--- [Setup] Keys generated. Constraints: %d | PK: %d bytes | VK: %d bytes", nbConstraints, pkSize, vkSize)
}

// --- 3. Helpers ---

// Modified to handle arbitrary number of inputs for both Commitment and Binding steps
func computeMimcHashGeneric(inputs ...*big.Int) *big.Int {
	h := cryptoMimc.NewMiMC()
	for _, val := range inputs {
		var f fr.Element
		f.SetBigInt(val)
		b := f.Bytes()
		h.Write(b[:])
	}

	sumBytes := h.Sum(nil)
	var resFr fr.Element
	resFr.SetBytes(sumBytes)
	var resBig big.Int
	resFr.BigInt(&resBig)
	return &resBig
}

func serializeToBase64(obj interface {
	WriteTo(w io.Writer) (int64, error)
}) (string, error) {
	var buf bytes.Buffer
	if _, err := obj.WriteTo(&buf); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func deserializeFromBase64(data string, obj interface {
	ReadFrom(r io.Reader) (int64, error)
}) error {
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return err
	}
	_, err = obj.ReadFrom(bytes.NewReader(b))
	return err
}

// --- 5. Handlers ---

type ProveRequest struct {
	Secret    []int64 `json:"secret"`
	Candidate []int64 `json:"candidate"`
	Password  string  `json:"password"`
	Salt      string  `json:"salt"`
	Challenge string  `json:"challenge"`
}

type ProveResponse struct {
	Proof         string `json:"proof"`
	PublicWitness string `json:"public_witness"`
	Commitment    string `json:"commitment"`
	// Metrics Fields
	NbConstraints int `json:"nb_constraints"`
	PkSize        int `json:"pk_size_bytes"`
	VkSize        int `json:"vk_size_bytes"`
}

type VerifyRequest struct {
	Proof      string `json:"proof"`
	Commitment string `json:"commitment"`
	Challenge  string `json:"challenge"`
}

type VerifyResponse struct {
	Valid bool `json:"valid"`
}

func proveHandler(w http.ResponseWriter, r *http.Request) {
	var req ProveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if len(req.Candidate) == 0 {
		req.Candidate = req.Secret
	}

	secretBig := make([]*big.Int, FeatureSize)
	candidateBig := make([]*big.Int, FeatureSize)
	for i := 0; i < FeatureSize; i++ {
		secretBig[i] = new(big.Int).SetInt64(req.Secret[i])
		candidateBig[i] = new(big.Int).SetInt64(req.Candidate[i])
	}

	// Parse Salt
	saltBig, _ := new(big.Int).SetString(req.Salt, 10)

	// Replace SHA256 with Argon2id for password storage security
	// Parameters: time=1, memory=64MB, threads=4, keyLen=32
	// We use the string salt as the salt bytes for Argon2
	passHash := argon2.IDKey([]byte(req.Password), []byte(req.Salt), 1, 64*1024, 4, 32)

	passwordBig := new(big.Int).SetBytes(passHash[:])

	// Ensure the hash is within the BN254 field range
	passwordBig.Mod(passwordBig, ecc.BN254.ScalarField())

	challengeBig := new(big.Int)
	if req.Challenge != "" {
		challengeBig, _ = new(big.Int).SetString(req.Challenge, 10)
	}

	// 1. Compute Base Commitment
	// We need this for the assignment and to return to the server
	commInputs := append(secretBig, passwordBig, saltBig)
	commitmentBig := computeMimcHashGeneric(commInputs...)

	// 2. Compute Bound Challenge
	// This is the public target that binds the proof to the session
	boundChallengeBig := computeMimcHashGeneric(commitmentBig, challengeBig)

	assignment := Circuit{
		Password:       passwordBig,
		Salt:           saltBig,
		Commitment:     commitmentBig,
		Challenge:      challengeBig,
		BoundChallenge: boundChallengeBig,
	}
	for i := 0; i < FeatureSize; i++ {
		assignment.Original[i] = secretBig[i]
		assignment.Current[i] = candidateBig[i]
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		http.Error(w, "Witness Failed", http.StatusInternalServerError)
		return
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		http.Error(w, "Proof Failed", http.StatusForbidden)
		return
	}

	publicWitness, _ := witness.Public()
	proofStr, _ := serializeToBase64(proof)
	pubWitnessStr, _ := serializeToBase64(publicWitness)

	json.NewEncoder(w).Encode(ProveResponse{
		Proof:         proofStr,
		PublicWitness: pubWitnessStr,
		Commitment:    commitmentBig.String(),
		NbConstraints: nbConstraints,
		PkSize:        pkSize,
		VkSize:        vkSize,
	})
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req VerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	proof := groth16.NewProof(ecc.BN254)
	if err := deserializeFromBase64(req.Proof, proof); err != nil {
		http.Error(w, "Invalid Proof", http.StatusBadRequest)
		return
	}

	commBig, _ := new(big.Int).SetString(req.Commitment, 10)
	challBig, _ := new(big.Int).SetString(req.Challenge, 10)

	// Reconstruct the BoundChallenge on the server side using TRUSTED data
	boundChallengeBig := computeMimcHashGeneric(commBig, challBig)

	publicAssignment := Circuit{
		Commitment:     commBig,
		Challenge:      challBig,
		BoundChallenge: boundChallengeBig,
	}

	publicWitness, err := frontend.NewWitness(&publicAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		http.Error(w, "Witness Reconstruction Failed", http.StatusBadRequest)
		return
	}

	err = groth16.Verify(proof, vk, publicWitness)
	isValid := (err == nil)

	if isValid {
		log.Println("[Verify] Success: Proof matches Trusted Commitment + Nonce.")
	} else {
		log.Printf("[Verify] Failure: %v", err)
	}

	json.NewEncoder(w).Encode(VerifyResponse{Valid: isValid})
	log.Printf("[Verify] Completed in %v | Valid: %v", time.Since(start), isValid)
}

func main() {
	initZKP()
	http.HandleFunc("/prove", proveHandler)
	http.HandleFunc("/verify", verifyHandler)
	log.Printf(">>> Go Fuzzy-ZKP Service listening on :8080 <<<")
	http.ListenAndServe(":8080", nil)
}
