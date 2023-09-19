// Copyright 2023 Song Z, 2020 ConsenSys AG
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
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/selector"
)

type Circuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	Jwt             []uints.U8 `gnark:",private"`
	ClaimedIdentity []uints.U8 `gnark:",private"`

	IdentityOffset frontend.Variable `gnark:",private"`

	JwtHash             [32]uints.U8 `gnark:",public"`
	ClaimedIdentityHash [32]uints.U8 `gnark:",public"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	// the U32 constrainer
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	/* the sha256 proof */
	{
		// sha256 proof of jwt
		h, err := sha2.New(api)
		if err != nil {
			return err
		}

		h.Write(circuit.Jwt)
		res := h.Sum()
		if len(res) != 32 {
			return fmt.Errorf("not 32 bytes")
		}

		for i := range circuit.JwtHash {
			uapi.ByteAssertEq(circuit.JwtHash[i], res[i])
		}
	}

	{
		// sha256 proof of the user claimed identity
		h, err := sha2.New(api)
		if err != nil {
			return err
		}

		h.Write(circuit.ClaimedIdentity)
		res := h.Sum()
		if len(res) != 32 {
			return fmt.Errorf("not 32 bytes")
		}
		for i := range circuit.ClaimedIdentityHash {
			uapi.ByteAssertEq(circuit.ClaimedIdentityHash[i], res[i])
		}
	}

	/* the inclusion proof */
	if len(circuit.Jwt) != 0 && len(circuit.ClaimedIdentity) != 0 {
		rawJwt := make([]frontend.Variable, len(circuit.Jwt))
		for index, elem := range circuit.Jwt {
			rawJwt[index] = elem.Val
		}

		maskedJwt := selector.Slice(api, circuit.IdentityOffset,
			api.Add(circuit.IdentityOffset, len(circuit.ClaimedIdentity)),
			rawJwt,
		)

		var identityAccumulator frontend.Variable
		identityAccumulator = 0
		for index, elem := range circuit.ClaimedIdentity {
			identityAccumulator = api.Add(
				identityAccumulator,
				api.Mul(elem.Val, api.Add(index, circuit.IdentityOffset)),
			)
		}

		var maskedJwtAccumulator frontend.Variable
		maskedJwtAccumulator = 0
		for index, elem := range maskedJwt {
			maskedJwtAccumulator = api.Add(
				maskedJwtAccumulator,
				api.Mul(elem, index),
			)
		}

		api.AssertIsEqual(identityAccumulator, maskedJwtAccumulator)
	}

	return nil
}
