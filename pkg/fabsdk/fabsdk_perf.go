//go:build pprof
// +build pprof

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fabsdk

import (
	"github.com/hxx258456/fabric-sdk-go-gm/internal/github.com/hxx258456/fabric-gm/core/operations"
	flogging "github.com/hxx258456/fabric-sdk-go-gm/internal/github.com/hxx258456/fabric-gm/sdkpatch/logbridge"
	"github.com/hxx258456/fabric-sdk-go-gm/pkg/fabsdk/metrics"
)

// initMetrics will initialize the Go SDK's metric's system instance to allow capturing metrics data by the SDK clients.
func (sdk *FabricSDK) initMetrics(configs *configs) {
	if configs == nil {
		return
	}

	system := newOperationsSystem(configs)

	err := system.Start()
	if err != nil {
		panic("metrics failed to start: " + err.Error())
	}

	// for now NewClientMetrics supports channel client. TODO: if other client types require metrics tracking, update this function
	sdk.clientMetrics = metrics.NewClientMetrics(system.Provider)
}

func newOperationsSystem(configs *configs) *operations.System {
	opsConfig := configs.metricsConfig.OperationCfg()
	metricsConfig := configs.metricsConfig.MetricCfg()
	return operations.NewSystem(operations.Options{
		Logger:        flogging.MustGetLogger("operations.runner"),
		ListenAddress: opsConfig.ListenAddress,
		Metrics: operations.MetricsOptions{
			Provider: metricsConfig.Provider,
			Statsd: &operations.Statsd{
				Network:       metricsConfig.Statsd.Network,
				Address:       metricsConfig.Statsd.Address,
				WriteInterval: metricsConfig.Statsd.WriteInterval,
				Prefix:        metricsConfig.Statsd.Prefix,
			},
		},
		TLS: operations.TLS{
			Enabled:            opsConfig.TLSEnabled,
			CertFile:           opsConfig.TLSCertFile,
			KeyFile:            opsConfig.TLSKeyFile,
			ClientCertRequired: opsConfig.ClientAuthRequired,
			ClientCACertFiles:  opsConfig.ClientRootCAs,
		},
		Version: "latest", // TODO expose version somewhere, Fabric uses 'metadata.Version'
	})
}
