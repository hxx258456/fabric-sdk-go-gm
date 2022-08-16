/*
Copyright IBM Corp. 2017 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw

import (
	"errors"
	"fmt"

	"github.com/hxx258456/fabric-sdk-go-gm/internal/github.com/hxx258456/fabric-gm/bccsp"
)

/*
bccsp/sw/keyderiv.go 部分密钥驱动实现
国密对应: 去除ecdsa与aes的密钥派生实现，改为不支持。
*/

type smPublicKeyKeyDeriver struct{}

func (kd *smPublicKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	return nil, errors.New("not implemented")
}

type ecdsaPublicKeyKeyDeriver struct{}

func (kd *ecdsaPublicKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	return nil, fmt.Errorf("unsupported 'KeyDerivOpts' provided [%v]", opts)
}

type ecdsaPrivateKeyKeyDeriver struct{}

func (kd *ecdsaPrivateKeyKeyDeriver) KeyDeriv(key bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	return nil, fmt.Errorf("unsupported 'KeyDerivOpts' provided [%v]", opts)
}

type aesPrivateKeyKeyDeriver struct {
	// conf *config
}

func (kd *aesPrivateKeyKeyDeriver) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (bccsp.Key, error) {
	return nil, fmt.Errorf("unsupported 'KeyDerivOpts' provided [%v]", opts)
}
