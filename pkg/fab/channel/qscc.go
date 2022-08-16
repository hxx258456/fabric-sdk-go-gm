/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package channel

/*
pkg/fab/channel/qscc.go qscc合约调用请求生成器，用于查询通道上的各类信息

GetTransactionByID : 根据ID查询交易
GetChainInfo : 获取区块链信息
GetBlockByHash : 根据区块Hash获取区块
GetBlockByNumber : 根据区块编号获取区块
GetBlockByTxID : 根据交易ID获取区块
*/

import (
	"strconv"

	"github.com/hxx258456/fabric-sdk-go-gm/pkg/common/providers/fab"
)

const (
	qscc                = "qscc"
	qsccTransactionByID = "GetTransactionByID"
	qsccChannelInfo     = "GetChainInfo"
	qsccBlockByHash     = "GetBlockByHash"
	qsccBlockByNumber   = "GetBlockByNumber"
	qsccBlockByTxID     = "GetBlockByTxID"
)

func createTransactionByIDInvokeRequest(channelID string, transactionID fab.TransactionID) fab.ChaincodeInvokeRequest {
	var args [][]byte
	args = append(args, []byte(channelID))
	args = append(args, []byte(transactionID))

	cir := fab.ChaincodeInvokeRequest{
		ChaincodeID: qscc,
		Fcn:         qsccTransactionByID,
		Args:        args,
	}
	return cir
}

func createChannelInfoInvokeRequest(channelID string) fab.ChaincodeInvokeRequest {
	var args [][]byte
	args = append(args, []byte(channelID))

	cir := fab.ChaincodeInvokeRequest{
		ChaincodeID: qscc,
		Fcn:         qsccChannelInfo,
		Args:        args,
	}
	return cir
}

// 创建GetBlockByHash的请求数据 fab.ChaincodeInvokeRequest:
//  ChaincodeID: "qscc",
//  Fcn: "GetBlockByHash",
//  Lang: ChaincodeSpec_UNDEFINED (0),
//  TransientMap: map[string][]uint8 nil,
//  Args: [][]uint8 len: 2, cap: 2, [channelID,blockHash],
//  IsInit: false
func createBlockByHashInvokeRequest(channelID string, blockHash []byte) fab.ChaincodeInvokeRequest {

	var args [][]byte
	args = append(args, []byte(channelID))
	args = append(args, blockHash)

	cir := fab.ChaincodeInvokeRequest{
		ChaincodeID: qscc,
		Fcn:         qsccBlockByHash,
		Args:        args,
	}
	return cir
}

func createBlockByNumberInvokeRequest(channelID string, blockNumber uint64) fab.ChaincodeInvokeRequest {

	var args [][]byte
	args = append(args, []byte(channelID))
	args = append(args, []byte(strconv.FormatUint(blockNumber, 10)))

	cir := fab.ChaincodeInvokeRequest{
		ChaincodeID: qscc,
		Fcn:         qsccBlockByNumber,
		Args:        args,
	}
	return cir
}

func createBlockByTxIDInvokeRequest(channelID string, transactionID fab.TransactionID) fab.ChaincodeInvokeRequest {
	var args [][]byte
	args = append(args, []byte(channelID))
	args = append(args, []byte(transactionID))

	cir := fab.ChaincodeInvokeRequest{
		ChaincodeID: qscc,
		Fcn:         qsccBlockByTxID,
		Args:        args,
	}
	return cir
}
