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
	"encoding/json"
	"fmt"
	"github.com/sumup-oss/go-pkgs/executor/vault"
	"log"
	"reflect"
	"regexp"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"
)

var (
	newlinesRegex = regexp.MustCompile(`\r?\n`)
)

func resourceVaultSecret() *schema.Resource {
	return &schema.Resource{
		SchemaVersion: 1,
		Create:        vaultSecretWrite,
		Update:        vaultSecretWrite,
		Delete:        vaultSecretDelete,
		Read:          vaultSecretRead,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Full path where the secret will be written.",
			},
			"payload_json": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Encrypted, base64-encoded JSON secret payload to write.",
				StateFunc:   trimStringStateFunc,
				Sensitive:   true,
			},
		},
	}
}

func vaultSecretWrite(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*vault.Client)
	path := d.Get("path").(string)

	payloadJSON, ok := d.Get("payload_json").(string)
	if !ok {
		return fmt.Errorf(
			"non-string value for `payload_json` at %s. Actual: %#v",
			path,
			d.Get("payload_json"),
		)
	}

	data, err := decryptPayloadJson(client, path, payloadJSON)
	if err != nil {
		return err
	}

	log.Printf("[DEBUG] Writing encrypted Vault secret to %s", path)
	_, err = client.Write(path, data)
	if err != nil {
		return fmt.Errorf("error writing to Vault %s. Err: %s", path, err)
	}

	d.SetId(path)

	return vaultSecretRead(d, meta)
}

func vaultSecretDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*vault.Client)

	path := d.Id()

	log.Printf("[DEBUG] Deleting vault encrypted secret from %q", path)
	_, err := client.Delete(path)
	if err != nil {
		return fmt.Errorf("error deleting %q from Vault: %q", path, err)
	}

	// NOTE: `SetId` is called automatically if return value is nil
	return nil
}

func vaultSecretRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*vault.Client)
	path := d.Id()

	log.Printf("[DEBUG] Reading %s from Vault", path)

	payloadJSON, ok := d.Get("payload_json").(string)
	if !ok {
		return fmt.Errorf(
			"non-string value for `payload_json` at %s. Actual: %#v",
			path,
			d.Get("payload_json"),
		)
	}

	cleanPayloadJSON := newlinesRegex.ReplaceAllString(payloadJSON, "")
	currentData, err := decryptPayloadJson(client, path, cleanPayloadJSON)
	if err != nil {
		return fmt.Errorf(
			"failed to decrypt current `payload_json` at %s. Err: %s",
			path,
			err,
		)
	}

	secret, err := client.Read(path)
	if err != nil {
		// NOTE: Don't remove from terraform state,
		// since it might be a network connectivity problem to Vault.
		return fmt.Errorf("error reading from Vault. Err: %s", err)
	}
	if secret == nil {
		log.Printf("[WARN] secret %s not found, removing from state", path)
		d.SetId("")
		return nil
	}

	// NOTE: Manually compare difference since we're using
	// encrypted data in terraform resources against plain-text Vault retrieved content.
	// We don't want to leak what the actual plaintext value is in stdout/stderr.
	if len(currentData) != len(secret.Data) {
		d.SetId("")
		return nil
	}

	// NOTE: Order of insertion of map keys is not important.
	// It'll actually compare the content.
	if !reflect.DeepEqual(currentData, secret.Data) {
		// NOTE: Don't set diff between local state and external Vault
		// cause it'll leak the plaintext value.
		d.SetId("")
		return nil
	}

	return nil
}

func decryptPayloadJson(client *vault.Client, path, payloadJSON string) (map[string]interface{}, error) {
	osExecutor := &os.RealOsExecutor{}
	b64Svc := base64.NewBase64Service()
	rsaSvc := rsa.NewRsaService(osExecutor)
	aesSvc := aes.NewAesService(pkcs7.NewPkcs7Service())

	encPayloadSvc := payload.NewEncryptedPayloadService(
		header.NewHeaderService(),
		passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc),
		content.NewV1EncryptedContentService(b64Svc, aesSvc),
	)

	deserializedPayload, err := encPayloadSvc.Deserialize([]byte(payloadJSON))
	if err != nil {
		return nil,
			fmt.Errorf("unable to deserialize `payload_json` at %s. Err: %s", path, err)
	}

	decryptedPayload, err := encPayloadSvc.Decrypt(client.PrivateKey(), deserializedPayload)
	if err != nil {
		return nil,
			fmt.Errorf("unable to decrypt `payload_json` at %s. Err: %s", path, err)
	}

	// NOTE: Since Vault is providing a JSON REST API,
	// sent `data` must be JSON object with keys.
	// Anything in the keys is written in Vault.
	var data map[string]interface{}
	err = json.Unmarshal(decryptedPayload.Content.Plaintext, &data)
	if err != nil {
		return nil,
			fmt.Errorf(
				"unable to unmarshal `payload_json` at path: %s. Syntax error: %s",
				path,
				err,
			)
	}
	return data, nil
}
