package main

import (
	"crypto/sha256"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"

	"gnark-jwt/jwt"
)

func main() {
	// compiles our circuit into a R1CS
	var circuit jwt.Circuit
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)

	// groth16 zkSNARK: Setup
	pk, vk, _ := groth16.Setup(ccs)

	jwtString := "{\"iss\":\"https://dev-9h47ajc9.us.au111th0.com/\",\"sub\":\"twitter|337834122\",\"aud\":\"123\",\"iat\":1639173028,\"exp\":1639209028,\"nonce\":\"44017a89\"}"
	claimedIdentityString := "twitter|337834122"

	jwtBytes := []byte(jwtString)
	claimedIdentityBytes := []byte(claimedIdentityString)

	jwtDigest := sha256.Sum256(jwtBytes)
	claimedIdentityDigest := sha256.Sum256(claimedIdentityBytes)

	// witness definition
	assignment := jwt.Circuit{
		Jwt:             uints.NewU8Array(jwtBytes),
		ClaimedIdentity: uints.NewU8Array(claimedIdentityBytes),
		IdentityOffset:  strings.Index(jwtString, claimedIdentityString),
	}

	copy(assignment.JwtHash[:], uints.NewU8Array(jwtDigest[:]))
	copy(assignment.ClaimedIdentityHash[:], uints.NewU8Array(claimedIdentityDigest[:]))

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	publicWitness, _ := witness.Public()

	// groth16: Prove & Verify
	proof, _ := groth16.Prove(ccs, pk, witness)
	groth16.Verify(proof, vk, publicWitness)
}
