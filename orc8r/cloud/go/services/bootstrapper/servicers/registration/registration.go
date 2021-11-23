package registration

import (
	"context"
	"fmt"

	"magma/orc8r/cloud/go/orc8r"
	"magma/orc8r/cloud/go/serdes"
	"magma/orc8r/cloud/go/services/bootstrapper"
	"magma/orc8r/cloud/go/services/device"
	models2 "magma/orc8r/cloud/go/services/orchestrator/obsidian/models"
	"magma/orc8r/cloud/go/services/tenants"
	"magma/orc8r/lib/go/protos"

	"github.com/go-openapi/strfmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type registrationServicer struct {
}

func NewRegistrationServicer() (protos.RegistrationServer, error) {
	return &registrationServicer{}, nil
}

func (rs *registrationServicer) Register(c context.Context, request *protos.RegisterRequest) (*protos.RegisterResponse, error) {
	nonce := nonceFromToken(request.Token)

	deviceInfo, err := bootstrapper.GetGatewayDeviceInfo(context.Background(), nonce)
	if err != nil {
		return formatRegisterResponseError(
			fmt.Sprintf("Could not get device info from nonce %v: %v", nonce, err),
		), nil
	}

	err = registerDevice(*deviceInfo, *request.Hwid, *request.ChallengeKey)
	if err != nil {
		return formatRegisterResponseError(fmt.Sprintf("Error registering device: %v", err)), nil
	}

	controlProxy, err := getControlProxy(deviceInfo.NetworkId)
	if err != nil {
		return formatRegisterResponseError(fmt.Sprintf("Error getting control proxy: %v", err)), nil
	}

	res := &protos.RegisterResponse{
		Response: &protos.RegisterResponse_ControlProxy{
			ControlProxy: controlProxy,
		},
	}
	return res, nil
}

func registerDevice(ti protos.GatewayDeviceInfo, hwid protos.AccessGatewayID, challengeKey protos.ChallengeKey) error {
	cKey := strfmt.Base64(challengeKey.Key)
	gatewayRecord := &models2.GatewayDevice{HardwareID: hwid.Id,
		Key: &models2.ChallengeKey{KeyType: challengeKey.KeyType.String(),
			Key: &cKey}}
	err := device.RegisterDevice(context.Background(), ti.NetworkId, orc8r.AccessGatewayRecordType, hwid.Id, gatewayRecord, serdes.Device)
	return err
}

func getControlProxy(networkID string) (string, error) {
	ten, err := tenants.GetAllTenants(context.Background())
	if err != nil {
		return "", err
	}
	var tID int64
	tIDFound := false
	for _, t := range ten.GetTenants() {
		for _, n := range t.Tenant.Networks {
			if n == networkID {
				tID = t.Id
				tIDFound = true
				break
			}
		}
	}

	if tIDFound == false {
		return "", status.Errorf(codes.NotFound, "TenantID for current NetworkID %d not found", networkID)
	}

	cp, err := tenants.GetControlProxy(context.Background(), tID)
	if err != nil {
		return "", err
	}

	return cp.ControlProxy, nil
}

func formatRegisterResponseError(errString string) *protos.RegisterResponse {
	errRes := &protos.RegisterResponse{
		Response: &protos.RegisterResponse_Error{
			Error: errString,
		},
	}
	return errRes
}
