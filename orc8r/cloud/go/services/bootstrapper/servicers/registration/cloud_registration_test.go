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

package registration_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"magma/orc8r/cloud/go/clock"
	"magma/orc8r/cloud/go/services/bootstrapper"
	"magma/orc8r/cloud/go/services/bootstrapper/servicers/registration"
	"magma/orc8r/cloud/go/test_utils"
	"magma/orc8r/lib/go/protos"

	"github.com/stretchr/testify/assert"
)

var (
	exampleRootCA = "exampleRootCA"
)

func TestCloudRegistrationServicer_GetGatewayRegistrationInfo(t *testing.T) {
	factory := test_utils.NewSQLBlobstore(t, bootstrapper.BlobstoreTableName)
	s := registration.NewBlobstoreStore(factory)

	c, err := registration.NewCloudRegistrationServicer(s, exampleRootCA, 30)
	assert.NoError(t, err)

	ctx := context.Background()

	getGatewayRegistrationInfoRes, err := c.GetGatewayRegistrationInfo(ctx, &protos.GetGatewayRegistrationInfoRequest{})
	assert.NoError(t, err)
	assert.Equal(t, exampleRootCA, getGatewayRegistrationInfoRes.RootCa)
	assert.Equal(t, registration.NotImplementedWarning, getGatewayRegistrationInfoRes.DomainName)
}

// TestCloudRegistrationServicer_Registration tests GetGatewayDeviceInfo and GetToken functionality
func TestCloudRegistrationServicer_Registration(t *testing.T) {
	var (
		exampleNetworkID = "exampleNetworkID"
		exampleLogicalID = "exampleLogicalID"
		exampleTimeout = 30*time.Minute

		gatewayDeviceInfo = &protos.GatewayDeviceInfo{
			NetworkId: exampleNetworkID,
			LogicalId: exampleLogicalID,
		}
	)

	factory := test_utils.NewSQLBlobstore(t, bootstrapper.BlobstoreTableName)
	s := registration.NewBlobstoreStore(factory)

	c, err := registration.NewCloudRegistrationServicer(s, exampleRootCA, exampleTimeout)
	assert.NoError(t, err)

	ctx := context.Background()

	nonce := registration.GenerateNonce(registration.NonceLength)
	assert.Equal(t, registration.NonceLength, len(nonce))
	token := registration.NonceToToken(nonce)
	assert.Equal(t, nonce, registration.NonceFromToken(token))

	// Try getting device info when token is invalid
	getGatewayDeviceInfoRes, err := c.GetGatewayDeviceInfo(ctx, &protos.GetGatewayDeviceInfoRequest{Token: token})
	assert.NoError(t, err)
	assert.Equal(t, &protos.GetGatewayDeviceInfoResponse_Error{
		Error: fmt.Sprintf("could not get token info from token %v: %v", token, "Not found"),
	}, getGatewayDeviceInfoRes.Response)

	// Register some device info
	getTokenRes, err := c.GetToken(ctx, &protos.GetTokenRequest{
		GatewayDeviceInfo: gatewayDeviceInfo,
		Refresh: false,
	})
	assert.NoError(t, err)
	assert.True(t, clock.Now().Before(time.Unix(getTokenRes.Timeout.Seconds, int64(getTokenRes.Timeout.Nanos))))
	token = getTokenRes.Token
	timeout := getTokenRes.Timeout

	// Get device info
	getGatewayDeviceInfoRes, err = c.GetGatewayDeviceInfo(ctx, &protos.GetGatewayDeviceInfoRequest{Token: token})
	assert.NoError(t, err)
	assert.Equal(t, &protos.GetGatewayDeviceInfoResponse_GatewayDeviceInfo{GatewayDeviceInfo: gatewayDeviceInfo}, getGatewayDeviceInfoRes.Response)

	// Refresh device info
	getTokenRes, err = c.GetToken(ctx, &protos.GetTokenRequest{
		GatewayDeviceInfo: gatewayDeviceInfo,
		Refresh: true,
	})
	assert.NoError(t, err)
	assert.True(t, time.Unix(timeout.Seconds, int64(timeout.Nanos)).Before(time.Unix(getTokenRes.Timeout.Seconds, int64(getTokenRes.Timeout.Nanos))))
	assert.NotEqual(t, token, getTokenRes.Token)

	// Get device info with new token
	getGatewayDeviceInfoRes, err = c.GetGatewayDeviceInfo(ctx, &protos.GetGatewayDeviceInfoRequest{Token: getTokenRes.Token})
	assert.NoError(t, err)
	assert.Equal(t, &protos.GetGatewayDeviceInfoResponse_GatewayDeviceInfo{GatewayDeviceInfo: gatewayDeviceInfo}, getGatewayDeviceInfoRes.Response)

	// Old token should still work
	getGatewayDeviceInfoRes, err = c.GetGatewayDeviceInfo(ctx, &protos.GetGatewayDeviceInfoRequest{Token: token})
	assert.NoError(t, err)
	assert.Equal(t, &protos.GetGatewayDeviceInfoResponse_GatewayDeviceInfo{GatewayDeviceInfo: gatewayDeviceInfo}, getGatewayDeviceInfoRes.Response)

	clock.SetAndFreezeClock(t, time.Now().Add(exampleTimeout))

	// Token should be expired
	getGatewayDeviceInfoRes, err = c.GetGatewayDeviceInfo(ctx, &protos.GetGatewayDeviceInfoRequest{Token: getTokenRes.Token})
	assert.NoError(t, err)
	assert.Equal(t, &protos.GetGatewayDeviceInfoResponse_Error{
		Error: fmt.Sprintf("token %v has expired", getTokenRes.Token),
	}, getGatewayDeviceInfoRes.Response)}
