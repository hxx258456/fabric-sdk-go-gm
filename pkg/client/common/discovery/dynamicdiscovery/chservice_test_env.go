//go:build testing
// +build testing

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package dynamicdiscovery

import (
	contextAPI "github.com/hxx258456/fabric-sdk-go-gm/pkg/common/providers/context"
	"github.com/hxx258456/fabric-sdk-go-gm/pkg/fab/discovery"
)

// SetClientProvider overrides the discovery client provider for unit tests
func SetClientProvider(provider func(ctx contextAPI.Client) (discovery.Client, error)) {
	clientProvider = provider
}
