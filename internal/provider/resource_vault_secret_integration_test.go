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
	"crypto/rand"
	stdRsa "crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	stdOs "os"
	"reflect"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/acctest"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/executor/vault"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/go-pkgs/testutils"
	"github.com/sumup-oss/vaulted/pkg/aes"
	"github.com/sumup-oss/vaulted/pkg/base64"
	"github.com/sumup-oss/vaulted/pkg/pkcs7"
	"github.com/sumup-oss/vaulted/pkg/rsa"
	"github.com/sumup-oss/vaulted/pkg/vaulted/content"
	"github.com/sumup-oss/vaulted/pkg/vaulted/header"
	"github.com/sumup-oss/vaulted/pkg/vaulted/passphrase"
	"github.com/sumup-oss/vaulted/pkg/vaulted/payload"

	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func generateRSAprivateKey(t *testing.T) ([]byte, *stdRsa.PrivateKey) {
	privKey, err := stdRsa.GenerateKey(rand.Reader, 2048)
	require.Nil(t, err)

	return pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privKey),
		},
	), privKey
}

func testResourceSecretConfig(path, payloadJSON string) string {
	return fmt.Sprintf(`
resource "vaulted_vault_secret" "test" {
   path = "%s"
   payload_json = "%s"
}`,
		path,
		payloadJSON,
	)
}

func testActVaultSecretCheckUpdate(
	provider *schema.Provider,
	expected map[string]interface{},
) func(state *terraform.State) error {
	return func(state *terraform.State) error {
		resourceState := state.Modules[0].Resources["vaulted_vault_secret.test"]
		instanceState := resourceState.Primary

		path := instanceState.ID

		meta := provider.Meta()
		client, ok := meta.(*vault.Client)
		if !ok {
			return fmt.Errorf(
				"error getting meta of provider. " +
					"very likely that test case provisioning has failed",
			)
		}

		secret, err := client.Read(path)
		if err != nil {
			return fmt.Errorf("error reading back secret: %s", err)
		}

		if !reflect.DeepEqual(secret.Data, expected) {
			return fmt.Errorf(
				"mismatched update assert. expected: %#v, actual: %#v",
				expected,
				secret.Data,
			)
		}

		return nil
	}
}

func TestResourceVaultSecretIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping testing in short mode")
	}

	t.Run("with VAULT_PRIVATE_KEY_PATH specified", func(t *testing.T) {
		t.Run(
			"with no pre-existing state, it is applied and destroyed successfully",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privkeyPath, privKey := testutils.GenerateAndWritePrivateKey(
					t,
					tmpDir,
					"priv.key",
				)

				err := stdOs.Setenv("VAULT_PRIVATE_KEY_PATH", privkeyPath)
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				contentArg := map[string]string{
					"foo": "bar",
				}

				serializedContent, err := json.Marshal(contentArg)
				require.Nil(t, err)

				payload := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent(serializedContent),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payload)
				require.Nil(t, err)

				serializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				providerFactory := NewProviderFactory("dev")

				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						Steps: []resource.TestStep{
							{
								Config: testResourceSecretConfig(
									path,
									string(serializedEncPayload),
								),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(serializedEncPayload),
									),
								),
							},
						},
					},
				)

				meta := providerFactory.Provider().Meta()
				client, ok := meta.(*vault.Client)
				if !ok {
					t.Fatalf(
						"error getting meta of provider. "+
							"very likely that test case provisioning has failed. Err: %s",
						err,
					)
				}

				secret, err := client.Read(path)
				require.Nil(t, err)
				assert.Nil(t, secret.Data)
			},
		)

		t.Run(
			"with no pre-existing state, but with non-JSON encrypted content, " +
				"it errors during plan",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privkeyPath, privKey := testutils.GenerateAndWritePrivateKey(
					t,
					tmpDir,
					"priv.key",
				)

				err := stdOs.Setenv("VAULT_PRIVATE_KEY_PATH", privkeyPath)
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				contentArg := "notJSON"
				payload := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent([]byte(contentArg)),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payload)
				require.Nil(t, err)

				serializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				providerFactory := NewProviderFactory("dev")

				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						Steps: []resource.TestStep{
							{
								PlanOnly: true,
								ExpectNonEmptyPlan: true,
								Config: testResourceSecretConfig(
									path,
									string(serializedEncPayload),
								),
								ExpectError: regexp.MustCompile("failed to decrypt current \\x60payload_json\\x60. Err: unable to unmarshal \\x60payload_json\\x60. Syntax error: invalid character 'o' in literal null.+"),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckNoResourceAttr(
										"vaulted_vault_secret.test",
										"path",
									),
									resource.TestCheckNoResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
									),
								),
							},
						},
					},
				)

				meta := providerFactory.Provider().Meta()
				client, ok := meta.(*vault.Client)
				if !ok {
					t.Fatalf(
						"error getting meta of provider. "+
							"very likely that test case provisioning has failed. Err: %s",
						err,
					)
				}

				secret, err := client.Read(path)
				require.Nil(t, err)
				assert.Nil(t, secret.Data)
			},
		)

		t.Run(
			"with existing resource that has actually different encrypted content (inside payload), "+
				"it is applied (updated)",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privkeyPath, privKey := testutils.GenerateAndWritePrivateKey(
					t,
					tmpDir,
					"priv.key",
				)

				err := stdOs.Setenv("VAULT_PRIVATE_KEY_PATH", privkeyPath)
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				oldContentArg := map[string]interface{}{
					"foo": "bar",
				}

				oldSerializedContent, err := json.Marshal(oldContentArg)
				require.Nil(t, err)

				payloadInstance := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent(oldSerializedContent),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				oldSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				newContentArg := map[string]interface{}{
					"foo": "newBAR",
				}

				newSerializedContent, err := json.Marshal(newContentArg)
				require.Nil(t, err)

				payloadInstance.Content = content.NewContent(newSerializedContent)

				encPayload, err = encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				newSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)


				providerFactory := NewProviderFactory("dev")
				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						Steps: []resource.TestStep{
							{
								Config: testResourceSecretConfig(
									path,
									string(oldSerializedEncPayload),
								),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(oldSerializedEncPayload),
									),
								),
							},
							{
								Config: testResourceSecretConfig(
									path,
									string(newSerializedEncPayload),
								),
								Check: testActVaultSecretCheckUpdate(
									providerFactory.Provider(),
									newContentArg,
								),
							},
						},
					},
				)

				meta := providerFactory.Provider().Meta()
				client, ok := meta.(*vault.Client)
				if !ok {
					t.Fatalf(
						"error getting meta of provider. "+
							"very likely that test case provisioning has failed. Err: %s",
						err,
					)
				}

				secret, err := client.Read(path)
				require.Nil(t, err)
				assert.Nil(t, secret.Data)
			},
		)

		t.Run(
			"with existing resource that has actually different non-JSON encrypted content (inside payload), "+
				"it errors during plan",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privkeyPath, privKey := testutils.GenerateAndWritePrivateKey(
					t,
					tmpDir,
					"priv.key",
				)

				err := stdOs.Setenv("VAULT_PRIVATE_KEY_PATH", privkeyPath)
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				oldContentArg := map[string]interface{}{
					"foo": "bar",
				}

				oldSerializedContent, err := json.Marshal(oldContentArg)
				require.Nil(t, err)

				payloadInstance := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent(oldSerializedContent),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				oldSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				payloadInstance.Content = content.NewContent([]byte("notJSON"))

				encPayload, err = encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				newSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)


				providerFactory := NewProviderFactory("dev")
				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						Steps: []resource.TestStep{
							{
								Config: testResourceSecretConfig(
									path,
									string(oldSerializedEncPayload),
								),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(oldSerializedEncPayload),
									),
								),
							},
							{
								PlanOnly: true,
								ExpectNonEmptyPlan: true,
								Config: testResourceSecretConfig(
									path,
									string(newSerializedEncPayload),
								),
								ExpectError: regexp.MustCompile("failed to decrypt current \\x60payload_json\\x60. Err: unable to unmarshal \\x60payload_json\\x60. Syntax error: invalid character 'o' in literal null.+"),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckNoResourceAttr(
										"vaulted_vault_secret.test",
										"path",
									),
									resource.TestCheckNoResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
									),
								),
							},
						},
					},
				)

				meta := providerFactory.Provider().Meta()
				client, ok := meta.(*vault.Client)
				if !ok {
					t.Fatalf(
						"error getting meta of provider. "+
							"very likely that test case provisioning has failed. Err: %s",
						err,
					)
				}

				secret, err := client.Read(path)
				require.Nil(t, err)
				assert.Nil(t, secret.Data)
			},
		)

		t.Run(
			"with existing resource that has actually the same encrypted content (inside payload), "+
				"it has no diff during plan, hence nothing is applied",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privkeyPath, privKey := testutils.GenerateAndWritePrivateKey(
					t,
					tmpDir,
					"priv.key",
				)

				err := stdOs.Setenv("VAULT_PRIVATE_KEY_PATH", privkeyPath)
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				oldContentArg := map[string]interface{}{
					"foo": "bar",
				}

				oldSerializedContent, err := json.Marshal(oldContentArg)
				require.Nil(t, err)

				payload := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent(oldSerializedContent),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payload)
				require.Nil(t, err)

				oldSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				encPayload, err = encPayloadSvc.Encrypt(&privKey.PublicKey, payload)
				require.Nil(t, err)

				newSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				assert.NotEqual(t, oldSerializedEncPayload, newSerializedEncPayload)

				providerFactory := NewProviderFactory("dev")

				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						Steps: []resource.TestStep{
							{
								Config: testResourceSecretConfig(
									path,
									string(oldSerializedEncPayload),
								),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(oldSerializedEncPayload),
									),
								),
							},
							{
								Config: testResourceSecretConfig(
									path,
									string(newSerializedEncPayload),
								),
								Check: testActVaultSecretCheckUpdate(
									providerFactory.Provider(),
									// NOTE: No changes,
									oldContentArg,
								),
							},
						},
					},
				)
			},
		)

		t.Run(
			"with applied resource, but deleted externally (via Vault directly)"+
				" that has actually the same encrypted content (inside payload), "+
				"it is applied, created and destroyed again",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privkeyPath, privKey := testutils.GenerateAndWritePrivateKey(
					t,
					tmpDir,
					"priv.key",
				)

				err := stdOs.Setenv("VAULT_PRIVATE_KEY_PATH", privkeyPath)
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				oldContentArg := map[string]interface{}{
					"foo": "bar",
				}

				oldSerializedContent, err := json.Marshal(oldContentArg)
				require.Nil(t, err)

				payload := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent(oldSerializedContent),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payload)
				require.Nil(t, err)

				oldSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				encPayload, err = encPayloadSvc.Encrypt(&privKey.PublicKey, payload)
				require.Nil(t, err)

				newSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				assert.NotEqual(t, oldSerializedEncPayload, newSerializedEncPayload)

				providerFactory := NewProviderFactory("dev")

				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						Steps: []resource.TestStep{
							{
								Config: testResourceSecretConfig(
									path,
									string(oldSerializedEncPayload),
								),
								Destroy: false,
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(oldSerializedEncPayload),
									),
								),
							},
							{
								PreConfig: func() {
									meta := providerFactory.Provider().Meta()
									client, ok := meta.(*vault.Client)
									if !ok {
										t.Fatalf(
											"error getting meta of"+
												" provider. "+
												"very likely that test case"+
												" provisioning has failed. Err: %s",
											err,
										)
									}
									secret, err := client.Read(path)
									require.Nil(t, err)

									// NOTE: Verify our secret actually existed
									// before deletion
									require.NotNil(t, secret.Data)

									_, err = client.Delete(path)
									require.Nil(t, err)
								},
								Config: testResourceSecretConfig(
									path,
									string(oldSerializedEncPayload),
								),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(oldSerializedEncPayload),
									),
								),
							},
						},
					},
				)
			},
		)
	})

	t.Run("with VAULT_PRIVATE_KEY_CONTENT specified", func(t *testing.T) {
		t.Run(
			"with no pre-existing state, it is applied and destroyed successfully",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privKeyContent, privKey := generateRSAprivateKey(t)
				err := stdOs.Setenv("VAULT_PRIVATE_KEY_CONTENT", string(privKeyContent))
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				contentArg := map[string]string{
					"foo": "bar",
				}

				serializedContent, err := json.Marshal(contentArg)
				require.Nil(t, err)

				payloadInstance := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent(serializedContent),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				serializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				providerFactory := NewProviderFactory("dev")

				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						//CheckDestroy: testActVaultSecretCheckDestroy(provider),
						Steps: []resource.TestStep{
							{
								Config: testResourceSecretConfig(
									path,
									string(serializedEncPayload),
								),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(serializedEncPayload),
									),
								),
							},
						},
					},
				)

				meta := providerFactory.Provider().Meta()
				client, ok := meta.(*vault.Client)
				if !ok {
					t.Fatalf(
						"error getting meta of provider. "+
							"very likely that test case provisioning has failed. Err: %s",
						err,
					)
				}

				secret, err := client.Read(path)
				require.Nil(t, err)
				assert.Nil(t, secret.Data)
			},
		)

		t.Run(
			"with no pre-existing state, but with non-JSON encrypted content, " +
				"it errors during plan",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privKeyContent, privKey := generateRSAprivateKey(t)
				err := stdOs.Setenv("VAULT_PRIVATE_KEY_CONTENT", string(privKeyContent))
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				payloadInstance := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent([]byte("notJSON")),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				serializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				providerFactory := NewProviderFactory("dev")

				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						//CheckDestroy: testActVaultSecretCheckDestroy(provider),
						Steps: []resource.TestStep{
							{
								PlanOnly: true,
								ExpectNonEmptyPlan: true,
								Config: testResourceSecretConfig(
									path,
									string(serializedEncPayload),
								),
								ExpectError: regexp.MustCompile("failed to decrypt current \\x60payload_json\\x60. Err: unable to unmarshal \\x60payload_json\\x60. Syntax error: invalid character 'o' in literal null.+"),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(serializedEncPayload),
									),
								),
							},
						},
					},
				)

				meta := providerFactory.Provider().Meta()
				client, ok := meta.(*vault.Client)
				if !ok {
					t.Fatalf(
						"error getting meta of provider. "+
							"very likely that test case provisioning has failed. Err: %s",
						err,
					)
				}

				secret, err := client.Read(path)
				require.Nil(t, err)
				assert.Nil(t, secret.Data)
			},
		)

		t.Run(
			"with existing resource that has actually different encrypted content (inside payload), "+
				"it is applied (updated)",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privKeyContent, privKey := generateRSAprivateKey(t)
				err := stdOs.Setenv("VAULT_PRIVATE_KEY_CONTENT", string(privKeyContent))
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				oldContentArg := map[string]interface{}{
					"foo": "bar",
				}

				oldSerializedContent, err := json.Marshal(oldContentArg)
				require.Nil(t, err)

				payloadInstance := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent(oldSerializedContent),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				oldSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				newContentArg := map[string]interface{}{
					"foo": "newBAR",
				}

				newSerializedContent, err := json.Marshal(newContentArg)
				require.Nil(t, err)

				payloadInstance.Content = content.NewContent(newSerializedContent)

				encPayload, err = encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				newSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				providerFactory := NewProviderFactory("dev")

				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						Steps: []resource.TestStep{
							{
								Config: testResourceSecretConfig(
									path,
									string(oldSerializedEncPayload),
								),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(oldSerializedEncPayload),
									),
								),
							},
							{
								Config: testResourceSecretConfig(
									path,
									string(newSerializedEncPayload),
								),
								Check: testActVaultSecretCheckUpdate(
									providerFactory.Provider(),
									newContentArg,
								),
							},
						},
					},
				)

				meta := providerFactory.Provider().Meta()
				client, ok := meta.(*vault.Client)
				if !ok {
					t.Fatalf(
						"error getting meta of provider. "+
							"very likely that test case provisioning has failed. Err: %s",
						err,
					)
				}

				secret, err := client.Read(path)
				require.Nil(t, err)
				assert.Nil(t, secret.Data)
			},
		)

		t.Run(
			"with existing resource that has actually different non-JSON encrypted content (inside payload), "+
				"it errors during plan",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privKeyContent, privKey := generateRSAprivateKey(t)
				err := stdOs.Setenv("VAULT_PRIVATE_KEY_CONTENT", string(privKeyContent))
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				oldContentArg := map[string]interface{}{
					"foo": "bar",
				}

				oldSerializedContent, err := json.Marshal(oldContentArg)
				require.Nil(t, err)

				payloadInstance := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent(oldSerializedContent),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				oldSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				payloadInstance.Content = content.NewContent([]byte("notJSON"))

				encPayload, err = encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				newSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				providerFactory := NewProviderFactory("dev")

				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						Steps: []resource.TestStep{
							{
								Config: testResourceSecretConfig(
									path,
									string(oldSerializedEncPayload),
								),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(oldSerializedEncPayload),
									),
								),
							},
							{
								PlanOnly: true,
								ExpectNonEmptyPlan: true,
								Config: testResourceSecretConfig(
									path,
									string(newSerializedEncPayload),
								),
								ExpectError: regexp.MustCompile("failed to decrypt current \\x60payload_json\\x60. Err: unable to unmarshal \\x60payload_json\\x60. Syntax error: invalid character 'o' in literal null.+"),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckNoResourceAttr(
										"vaulted_vault_secret.test",
										"path",
									),
									resource.TestCheckNoResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
									),
								),
							},
						},
					},
				)

				meta := providerFactory.Provider().Meta()
				client, ok := meta.(*vault.Client)
				if !ok {
					t.Fatalf(
						"error getting meta of provider. "+
							"very likely that test case provisioning has failed. Err: %s",
						err,
					)
				}

				secret, err := client.Read(path)
				require.Nil(t, err)
				assert.Nil(t, secret.Data)
			},
		)

		t.Run(
			"with existing resource that has actually the same encrypted content (inside payload), "+
				"it has no diff during plan, hence nothing is applied",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privKeyContent, privKey := generateRSAprivateKey(t)
				err := stdOs.Setenv("VAULT_PRIVATE_KEY_CONTENT", string(privKeyContent))
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				oldContentArg := map[string]interface{}{
					"foo": "bar",
				}

				oldSerializedContent, err := json.Marshal(oldContentArg)
				require.Nil(t, err)

				payloadInstance := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent(oldSerializedContent),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				oldSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				encPayload, err = encPayloadSvc.Encrypt(&privKey.PublicKey, payloadInstance)
				require.Nil(t, err)

				newSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				assert.NotEqual(t, oldSerializedEncPayload, newSerializedEncPayload)

				providerFactory := NewProviderFactory("dev")

				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						Steps: []resource.TestStep{
							{
								Config: testResourceSecretConfig(
									path,
									string(oldSerializedEncPayload),
								),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(oldSerializedEncPayload),
									),
								),
							},
							{
								Config: testResourceSecretConfig(
									path,
									string(newSerializedEncPayload),
								),
								Check: testActVaultSecretCheckUpdate(
									providerFactory.Provider(),
									// NOTE: No changes,
									oldContentArg,
								),
							},
						},
					},
				)
			},
		)

		t.Run(
			"with applied resource, but deleted externally (via Vault directly)"+
				" that has actually the same encrypted content (inside payload), "+
				"it is applied, created and destroyed again",
			func(t *testing.T) {
				osExecutor := &os.RealOsExecutor{}
				rsaSvc := rsa.NewRsaService(osExecutor)

				tmpDir := testutils.TestDir(t, "provider-vaulted")
				testutils.TestChdir(t, tmpDir)

				privKeyContent, privKey := generateRSAprivateKey(t)
				err := stdOs.Setenv("VAULT_PRIVATE_KEY_CONTENT", string(privKeyContent))
				require.Nil(t, err)

				b64Svc := base64.NewBase64Service()
				encPassphraseSvc := passphrase.NewEncryptedPassphraseService(b64Svc, rsaSvc)

				passphraseArg, err := encPassphraseSvc.GeneratePassphrase(32)
				if err != nil {
					log.Fatal(err)
				}

				encPayloadSvc := payload.NewEncryptedPayloadService(
					header.NewHeaderService(),
					encPassphraseSvc,
					content.NewV1EncryptedContentService(
						b64Svc,
						aes.NewAesService(pkcs7.NewPkcs7Service()),
					),
				)

				oldContentArg := map[string]interface{}{
					"foo": "bar",
				}

				oldSerializedContent, err := json.Marshal(oldContentArg)
				require.Nil(t, err)

				payload := payload.NewPayload(
					header.NewHeader(),
					passphraseArg,
					content.NewContent(oldSerializedContent),
				)
				path := acctest.RandomWithPrefix("secret/encrypted_test")

				encPayload, err := encPayloadSvc.Encrypt(&privKey.PublicKey, payload)
				require.Nil(t, err)

				oldSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				encPayload, err = encPayloadSvc.Encrypt(&privKey.PublicKey, payload)
				require.Nil(t, err)

				newSerializedEncPayload, err := encPayloadSvc.Serialize(encPayload)
				require.Nil(t, err)

				assert.NotEqual(t, oldSerializedEncPayload, newSerializedEncPayload)

				providerFactory := NewProviderFactory("dev")

				// NOTE: Don't enforce the `TF_ACC` environment variable requirement,
				// but still run it as an integration test.
				resource.UnitTest(
					t,
					resource.TestCase{
						ProviderFactories: providerFactory.ProviderFactories(),
						PreCheck:  func() { testAccPreCheck(t) },
						Steps: []resource.TestStep{
							{
								Config: testResourceSecretConfig(
									path,
									string(oldSerializedEncPayload),
								),
								Destroy: false,
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(oldSerializedEncPayload),
									),
								),
							},
							{
								PreConfig: func() {
									meta := providerFactory.Provider().Meta()
									client, ok := meta.(*vault.Client)
									if !ok {
										t.Fatalf(
											"error getting meta of"+
												" provider. "+
												"very likely that test case"+
												" provisioning has failed. Err: %s",
											err,
										)
									}
									secret, err := client.Read(path)
									require.Nil(t, err)

									// NOTE: Verify our secret actually existed
									// before deletion
									require.NotNil(t, secret.Data)

									_, err = client.Delete(path)
									require.Nil(t, err)
								},
								Config: testResourceSecretConfig(
									path,
									string(oldSerializedEncPayload),
								),
								Check: resource.ComposeTestCheckFunc(
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"path",
										path,
									),
									resource.TestCheckResourceAttr(
										"vaulted_vault_secret.test",
										"payload_json",
										string(oldSerializedEncPayload),
									),
								),
							},
						},
					},
				)
			},
		)
	})
}
