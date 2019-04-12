// Copyright 2018 SumUp Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package provider

import (
	stdRsa "crypto/rsa"
	"fmt"
	"io"
	"log"
	"path"
	"strings"

	"github.com/hashicorp/vault/api"
)

const (
	// latestVersion is specified when reading a secret
	// to retrieve the latest version of that secret in KV2 Vault API.
	latestVersion = -1
)

// Client enhances official Vault API client that does not provide easy capabilities
// to determine whether kv1 or kv2 secret engine is used.
type Client struct {
	vaultClient *api.Client
	privateKey  *stdRsa.PrivateKey
}

func newClient(vaultClient *api.Client, privateKey *stdRsa.PrivateKey) *Client {
	return &Client{
		vaultClient: vaultClient,
		privateKey:  privateKey,
	}
}

// Write writes `data` to `path` and handles both V1 and V2 KV secret API of Vault.
func (c *Client) Write(path string, data map[string]interface{}) (*api.Secret, error) {
	mountPath, v2, err := c.isKVv2(path)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to determine if remote Vault supports v2 or v1 kv secret storage. Err: %s",
			err,
		)
	}

	// NOTE: v2 api puts the data given inside a JSON key `data`.
	// ref: https://www.vaultproject.io/api/secret/kv/kv-v2.html#create-update-secret
	if v2 {
		path = c.addPrefixToVKVPath(path, mountPath, "data")
		data = map[string]interface{}{
			"data":    data,
			"options": map[string]interface{}{},
		}
	}

	secret, err := c.vaultClient.Logical().Write(path, data)
	if err != nil {
		return nil, fmt.Errorf("error writing to Vault %s. Err: %s", path, err)
	}
	return secret, err
}

// Write deletes secret at `path` and handles both V1 and V2 KV secret API of Vault.
func (c *Client) Delete(path string) (*api.Secret, error) {
	mountPath, v2, err := c.isKVv2(path)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to determine if remote Vault supports v2 or v1 kv secret storage. Err: %s",
			err,
		)
	}

	// NOTE: v2 api puts the data given inside a JSON key `data`.
	// ref: https://www.vaultproject.io/api/secret/kv/kv-v2.html#create-update-secret
	if v2 {
		path = c.addPrefixToVKVPath(path, mountPath, "data")
	}

	secret, err := c.vaultClient.Logical().Delete(path)
	if err != nil {
		return nil, fmt.Errorf("error writing to Vault %s. Err: %s", path, err)
	}
	return secret, err
}

// Read reads **latest** version of  secret at `path` and handles both V1 and V2 KV secret API of Vault.
func (c *Client) Read(path string) (*api.Secret, error) {
	mountPath, v2, err := c.isKVv2(path)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to determine if remote Vault supports v2 or v1 kv secret storage. Err: %s",
			err,
		)
	}

	// NOTE: v2 api puts the data given inside a JSON key `data`.
	// ref: https://www.vaultproject.io/api/secret/kv/kv-v2.html#create-update-secret
	var versionParam map[string]string

	if v2 {
		path = c.addPrefixToVKVPath(path, mountPath, "data")
		if err != nil {
			return nil, err
		}

		versionParam = map[string]string{
			"version": fmt.Sprintf("%d", latestVersion),
		}
	}

	secret, err := c.kvReadRequest(path, versionParam)
	if err != nil {
		return nil, err
	}

	if v2 && secret != nil {
		data, ok := secret.Data["data"]

		if ok && data != nil {
			dataMap, ok := data.(map[string]interface{})
			if ok {
				secret.Data = dataMap
			} else {
				// NOTE: It really makes no sense to be anything different than
				// a map, otherwise this means that fundamentally Vault has changed
				// its storage design and does not provide key-values at `path`.
				// However don't show the actual value, since it will leak plaintext secrets.
				log.Printf("[WARN] secret value at path %q is not a key-value map", path)
				secret.Data = nil
			}
		} else {
			secret.Data = nil
		}
	}

	return secret, nil
}

// kvPreflightVersionRequest executes a Vault API request for `path` to determine
// the version of the kv backend. It defaults to version 1 if it's not possible to get a version.
// Returned values are `mounthPath, version, error`
func (c *Client) kvPreflightVersionRequest(path string) (string, int, error) {
	currentWrappingLookupFunc := c.vaultClient.CurrentWrappingLookupFunc()
	c.vaultClient.SetWrappingLookupFunc(nil)
	defer c.vaultClient.SetWrappingLookupFunc(currentWrappingLookupFunc)

	r := c.vaultClient.NewRequest("GET", "/v1/sys/internal/ui/mounts/"+path)
	resp, err := c.vaultClient.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		// NOTE: If we get a 404 we are using an older version of vault,
		// default to version 1.
		// Hopefully v1 will be removed before v2 happens, otherwise this default is problematic.
		if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
			return "", 1, nil
		}

		return "", 0, err
	}

	secret, err := api.ParseSecret(resp.Body)
	if err != nil {
		return "", 0, err
	}
	var mountPath string
	if mountPathRaw, ok := secret.Data["path"]; ok {
		mountPath = mountPathRaw.(string)
	}
	options := secret.Data["options"]
	if options == nil {
		return mountPath, 1, nil
	}
	versionRaw := options.(map[string]interface{})["version"]
	if versionRaw == nil {
		return mountPath, 1, nil
	}
	version := versionRaw.(string)
	switch version {
	case "", "1":
		return mountPath, 1, nil
	case "2":
		return mountPath, 2, nil
	}

	return mountPath, 1, nil
}

// isKVv2 simply checks whether the secret storage behind `path` is kv 2 or not.
func (c *Client) isKVv2(path string) (string, bool, error) {
	mountPath, version, err := c.kvPreflightVersionRequest(path)
	if err != nil {
		return "", false, err
	}

	return mountPath, version == 2, nil
}

// addPrefixToVKVPath adds specified `apiPrefix` to returned path.
// It removes trailing `/` from `mountPath`.
// It's mostly useful for V2 KV API calls.
func (c *Client) addPrefixToVKVPath(pathArg, mountPath, apiPrefix string) string {
	switch {
	case pathArg == mountPath, pathArg == strings.TrimSuffix(mountPath, "/"):
		return path.Join(mountPath, apiPrefix)
	default:
		pathArg = strings.TrimPrefix(pathArg, mountPath)
		return path.Join(mountPath, apiPrefix, pathArg)
	}
}

func (c *Client) kvReadRequest(path string, params map[string]string) (*api.Secret, error) {
	r := c.vaultClient.NewRequest("GET", "/v1/"+path)
	for k, v := range params {
		r.Params.Set(k, v)
	}
	resp, err := c.vaultClient.RawRequest(r)
	if resp != nil {
		defer resp.Body.Close()
	}
	if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
		secret, parseErr := api.ParseSecret(resp.Body)
		switch parseErr {
		case nil:
		case io.EOF:
			return nil, nil
		default:
			return nil, err
		}
		if secret != nil && (len(secret.Warnings) > 0 || len(secret.Data) > 0) {
			return secret, nil
		}
		return secret, nil
	}
	if err != nil {
		return nil, err
	}

	return api.ParseSecret(resp.Body)
}
