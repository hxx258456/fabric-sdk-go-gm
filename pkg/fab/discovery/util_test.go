/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package discovery

import (
	"testing"

	"github.com/hxx258456/fabric-protos-go-gm/gossip"
	discclient "github.com/hxx258456/fabric-sdk-go-gm/internal/github.com/hxx258456/fabric-gm/discovery/client"
	gprotoext "github.com/hxx258456/fabric-sdk-go-gm/internal/github.com/hxx258456/fabric-gm/gossip/protoext"
	"github.com/hxx258456/fabric-sdk-go-gm/pkg/common/providers/fab"
	"github.com/hxx258456/fabric-sdk-go-gm/pkg/fab/discovery/mocks"
	"github.com/stretchr/testify/require"
)

func TestGetProperties(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		chaincodes := []*gossip.Chaincode{
			{
				Name:    "cc1",
				Version: "v1",
			},
		}

		endpoint := &discclient.Peer{
			StateInfoMessage: newStateInfoMessage(&mocks.MockDiscoveryPeerEndpoint{
				LedgerHeight: 1001,
				Chaincodes:   chaincodes,
				LeftChannel:  true,
			}),
		}

		properties := GetProperties(endpoint)
		require.NotEmpty(t, properties)
		require.Equal(t, uint64(1001), properties[fab.PropertyLedgerHeight])
		require.Equal(t, chaincodes, properties[fab.PropertyChaincodes])
		require.Equal(t, true, properties[fab.PropertyLeftChannel])
	})

	t.Run("Nil state info message", func(t *testing.T) {
		properties := GetProperties(&discclient.Peer{})
		require.Empty(t, properties)
	})

	t.Run("Nil properties in state info message", func(t *testing.T) {
		endpoint := &discclient.Peer{
			StateInfoMessage: &gprotoext.SignedGossipMessage{
				GossipMessage: &gossip.GossipMessage{
					Content: &gossip.GossipMessage_StateInfo{
						StateInfo: &gossip.StateInfo{},
					},
				},
			},
		}

		properties := GetProperties(endpoint)
		require.Empty(t, properties)
	})
}
