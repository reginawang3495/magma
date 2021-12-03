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

	"magma/orc8r/cloud/go/services/bootstrapper"
	"magma/orc8r/cloud/go/services/bootstrapper/servicers/registration"
	"magma/orc8r/cloud/go/services/tenants"
	tenantsTestInit "magma/orc8r/cloud/go/services/tenants/test_init"
	"magma/orc8r/lib/go/protos"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	registerRequest = &protos.RegisterRequest{
		Token: "someToken",
		Hwid: &protos.AccessGatewayID{
			Id: "Id",
		},
		ChallengeKey: &protos.ChallengeKey{
			KeyType: 0,
			Key:     []byte("key"),
		},
	}

	controlProxy = "controlProxy"
	nextTenantID int64 = 0
)

func TestRegistrationServicer_Register(t *testing.T) {
	reg, cleanup := setupTestRegistration(t)
	defer cleanup()

	res, err := reg.Register(nil, registerRequest)
	assert.NoError(t, err)
	expectedRes := &protos.RegisterResponse{
		Response: &protos.RegisterResponse_ControlProxy{ControlProxy: controlProxy},
	}
	assert.Equal(t, expectedRes, res)
}

func TestRegistrationServicer_Register_BadToken(t *testing.T) {
	rpcErr := status.Error(codes.NotFound, "errMessage")

	reg, cleanup := setupTestRegistration(t)
	defer cleanup()
	bootstrapper.GetGatewayDeviceInfo = func(ctx context.Context, token string) (*protos.GatewayDeviceInfo, error) {
		return nil, rpcErr
	}

	res, err := reg.Register(nil, registerRequest)
	assert.NoError(t, err)
	expectedRes := &protos.RegisterResponse{
		Response: &protos.RegisterResponse_Error{
			Error: fmt.Sprintf("could not get device info from token %v: %v", registerRequest.Token, rpcErr),
		},
	}
	assert.Equal(t, expectedRes, res)
}

func TestRegistrationServicer_Register_NoControlProxy(t *testing.T) {
	rpcErr := status.Error(codes.NotFound, "errMessage")

	reg, cleanup := setupTestRegistration(t)
	defer cleanup()
	registration.GetControlProxy = func(networkID string) (string, error) {
		return "", rpcErr
	}

	res, err := reg.Register(nil, registerRequest)
	assert.NoError(t, err)
	expectedRes := &protos.RegisterResponse{
		Response: &protos.RegisterResponse_Error{
			Error: fmt.Sprintf("error getting control proxy: %v", rpcErr),
		},
	}
	assert.Equal(t, expectedRes, res)
}

func TestGetControlProxy_NoNetworkID(t *testing.T) {
	setupAddNetworksToTenantsService(t)

	controlProxyRes, err := registration.GetControlProxy(networkID)
	assert.Equal(t, status.Errorf(codes.NotFound, "tenantID for current NetworkID %v not found", networkID), err)
	assert.Equal(t, "", controlProxyRes)
}

func TestGetControlProxy_NoControlProxy(t *testing.T) {
	setupAddNetworksToTenantsService(t)

	networkIDTenant := &protos.Tenant{
		Name:                 "tenant",
		Networks:             []string{networkID},
	}
	addTenant(t, networkIDTenant)

	controlProxyRes, err := registration.GetControlProxy(networkID)
	assert.Equal(t, "Not found", err.Error())
	assert.Equal(t, "", controlProxyRes)
}

func TestGetControlProxy(t *testing.T) {
	setupAddNetworksToTenantsService(t)

	networkIDTenant := &protos.Tenant{
		Name:                 "tenant",
		Networks:             []string{networkID},
	}
	id := addTenant(t, networkIDTenant)

	ctx := context.Background()
	err := tenants.CreateOrUpdateControlProxy(ctx, protos.CreateOrUpdateControlProxyRequest{
		Id:                   id,
		ControlProxy:         controlProxy,
	})
	assert.NoError(t, err)

	controlProxyRes, err := registration.GetControlProxy(networkID)
	assert.NoError(t, err)
	assert.Equal(t, controlProxy, controlProxyRes)
}

func setupTestRegistration(t *testing.T) (protos.RegistrationServer, func()) {
	tmpGetControlProxy := registration.GetControlProxy
	cleanup := func() {registration.GetControlProxy = tmpGetControlProxy}

	reg, err := registration.NewRegistrationServicer()
	assert.NoError(t, err)

	bootstrapper.GetGatewayDeviceInfo = func(ctx context.Context, token string) (*protos.GatewayDeviceInfo, error) {
		return gatewayDeviceInfo, nil
	}
	registration.RegisterDevice = func(deviceInfo protos.GatewayDeviceInfo, hwid *protos.AccessGatewayID, challengeKey *protos.ChallengeKey) error {
		return nil
	}
	registration.GetControlProxy = func(networkID string) (string, error) {
		return controlProxy, nil
	}
	return reg, cleanup
}

func setupAddNetworksToTenantsService(t *testing.T) {
	var (
		tenant1 = &protos.Tenant{
			Name:                 "tenant",
			Networks:             []string{"network1", "network2"},
		}
		tenant2 = &protos.Tenant{
			Name:                 "tenant",
			Networks:             []string{"network3", "network4"},
		}
	)
	tenantsTestInit.StartTestService(t)

	addTenant(t, tenant1)
	addTenant(t, tenant2)
}

func addTenant(t *testing.T, tenant *protos.Tenant) int64 {
	ctx := context.Background()

	tenantRes, err := tenants.CreateTenant(ctx, nextTenantID, tenant)
	assert.NoError(t, err)
	assert.Equal(t, tenant, tenantRes)

	nextTenantID = nextTenantID + 1
	return nextTenantID - 1
}
