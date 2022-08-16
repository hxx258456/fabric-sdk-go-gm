/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package comm

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/hxx258456/ccgo/grpc"
	pb "github.com/hxx258456/fabric-protos-go-gm/peer"
	eventmocks "github.com/hxx258456/fabric-sdk-go-gm/pkg/fab/events/mocks"
	"github.com/hxx258456/fabric-sdk-go-gm/pkg/fab/mocks"
)

const (
	peerAddress     = "localhost:9999"
	endorserAddress = "127.0.0.1:0"
	peerURL         = "grpc://" + peerAddress
)

func TestMain(m *testing.M) {
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	lis, err := net.Listen("tcp", peerAddress)
	if err != nil {
		panic(fmt.Sprintf("Error starting events listener %s", err))
	}

	testServer = eventmocks.NewMockDeliverServer()

	pb.RegisterDeliverServer(grpcServer, testServer)

	go grpcServer.Serve(lis)

	srvs, addrs, err := startEndorsers(30, endorserAddress)
	if err != nil {
		panic(fmt.Sprintf("Error starting endorser %s", err))
	}
	for _, srv := range srvs {
		defer srv.Stop()
	}
	endorserAddr = addrs

	os.Exit(m.Run())
}

func startEndorsers(count int, address string) ([]*mocks.MockEndorserServer, []string, error) {
	srvs := make([]*mocks.MockEndorserServer, 0, count)
	addrs := make([]string, 0, count)

	for i := 0; i < count; i++ {
		srv := &mocks.MockEndorserServer{}
		addr := srv.Start(address)
		srvs = append(srvs, srv)
		addrs = append(addrs, addr)
	}
	return srvs, addrs, nil
}
