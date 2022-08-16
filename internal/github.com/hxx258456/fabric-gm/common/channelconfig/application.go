/*
Copyright IBM Corp. 2017 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package channelconfig

import (
	cb "github.com/hxx258456/fabric-protos-go-gm/common"
	pb "github.com/hxx258456/fabric-protos-go-gm/peer"
	"github.com/hxx258456/fabric-sdk-go-gm/internal/github.com/hxx258456/fabric-gm/common/capabilities"
	"github.com/pkg/errors"
)

const (
	// ApplicationGroupKey is the group name for the Application config
	ApplicationGroupKey = "Application"

	// ACLsKey is the name of the ACLs config
	ACLsKey = "ACLs"
)

// ApplicationProtos is used as the source of the ApplicationConfig
type ApplicationProtos struct {
	ACLs         *pb.ACLs
	Capabilities *cb.Capabilities
}

// ApplicationConfig implements the Application interface
type ApplicationConfig struct {
	applicationOrgs map[string]ApplicationOrg
	protos          *ApplicationProtos
}

// NewApplicationConfig creates config from an Application config group
func NewApplicationConfig(appGroup *cb.ConfigGroup, mspConfig *MSPConfigHandler) (*ApplicationConfig, error) {
	ac := &ApplicationConfig{
		applicationOrgs: make(map[string]ApplicationOrg),
		protos:          &ApplicationProtos{},
	}

	if err := DeserializeProtoValuesFromGroup(appGroup, ac.protos); err != nil {
		return nil, errors.Wrap(err, "failed to deserialize values")
	}

	if !ac.Capabilities().ACLs() {
		if _, ok := appGroup.Values[ACLsKey]; ok {
			return nil, errors.New("ACLs may not be specified without the required capability")
		}
	}

	var err error
	for orgName, orgGroup := range appGroup.Groups {
		ac.applicationOrgs[orgName], err = NewApplicationOrgConfig(orgName, orgGroup, mspConfig)
		if err != nil {
			return nil, err
		}
	}

	return ac, nil
}

// Organizations returns a map of org ID to ApplicationOrg
func (ac *ApplicationConfig) Organizations() map[string]ApplicationOrg {
	return ac.applicationOrgs
}

// Capabilities returns a map of capability name to Capability
func (ac *ApplicationConfig) Capabilities() ApplicationCapabilities {
	return capabilities.NewApplicationProvider(ac.protos.Capabilities.Capabilities)
}

// APIPolicyMapper returns a PolicyMapper that maps API names to policies
func (ac *ApplicationConfig) APIPolicyMapper() PolicyMapper {
	pm := newAPIsProvider(ac.protos.ACLs.Acls)

	return pm
}