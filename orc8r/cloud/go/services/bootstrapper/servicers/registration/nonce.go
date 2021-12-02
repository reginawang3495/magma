/*
Copyright 2020 The Magma Authors.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree.

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package registration

import (
	"math/rand"
	"time"

	"magma/orc8r/cloud/go/clock"
	"magma/orc8r/cloud/go/services/bootstrapper"
	"magma/orc8r/lib/go/protos"
)

func IsExpired(t *protos.TokenInfo) bool {
	expirationTime := time.Unix(t.Timeout.Seconds, int64(t.Timeout.Nanos))
	return clock.Now().After(expirationTime)
}

func NonceToToken(nonce string) string {
	return bootstrapper.TokenPrefix + nonce
}

func NonceFromToken(token string) string {
	return token[len(bootstrapper.TokenPrefix):]
}

// GenerateNonce is sourced from https://stackoverflow.com/a/31832326
func GenerateNonce(n int) string {
	const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
