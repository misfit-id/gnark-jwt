// Copyright 2023 SongZ, 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package jwt

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

func TestJwt(t *testing.T) {
	jwtString := "{\"iss\":\"https://dev-9h47ajc9.us.au111th0.com/\",\"sub\":\"twitter|337834122\",\"aud\":\"123\",\"iat\":1639173028,\"exp\":1639209028,\"nonce\":\"44017a89\"}"
	claimedIdentityString := "twitter|337834122"

	jwt := []byte(jwtString)
	claimedIdentity := []byte(claimedIdentityString)

	jwtDigest := sha256.Sum256(jwt)
	claimedIdentityDigest := sha256.Sum256(claimedIdentity)

	witness := Circuit{
		Jwt:             uints.NewU8Array(jwt),
		ClaimedIdentity: uints.NewU8Array(claimedIdentity),
		IdentityOffset:  strings.Index(jwtString, claimedIdentityString),
	}

	copy(witness.JwtHash[:], uints.NewU8Array(jwtDigest[:]))
	copy(witness.ClaimedIdentityHash[:], uints.NewU8Array(claimedIdentityDigest[:]))

	err := test.IsSolved(&Circuit{
		Jwt:             make([]uints.U8, len(jwt)),
		ClaimedIdentity: make([]uints.U8, len(claimedIdentity)),
	}, &witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
}
