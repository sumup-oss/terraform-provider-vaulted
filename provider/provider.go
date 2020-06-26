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
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/hashicorp/terraform/plugin"
	"github.com/sumup-oss/go-pkgs/executor/vault"
	"github.com/sumup-oss/go-pkgs/logger"

	"github.com/hashicorp/terraform/helper/logging"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/config"
	"github.com/sumup-oss/go-pkgs/os"
	"github.com/sumup-oss/vaulted/pkg/rsa"
)

func FuncWithLogger(logger logger.Logger) plugin.ProviderFunc {
	return func() terraform.ResourceProvider {
		return provider(logger)
	}
}

func provider(logger logger.Logger) terraform.ResourceProvider {
	providerConfigureWithLogger := func(d *schema.ResourceData) (interface{}, error) {
		return providerConfigure(logger, d)
	}

	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"address": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_ADDR", nil),
				Description: "URL of the root of the target Vault server.",
			},
			"token": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_TOKEN", ""),
				Description: "Token to use to authenticate to Vault.",
			},
			"private_key_content": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_PRIVATE_KEY_CONTENT", ""),
				Description: "Content of private key used to decrypt `vaulted_vault_secret` resources. " +
					"This setting has higher priority than `private_key_path`.",
			},
			"private_key_path": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_PRIVATE_KEY_PATH", ""),
				Description: "Path to private key used to decrypt `vaulted_vault_secret` resources. " +
					"This setting has lower priority than `private_key_content`.",
			},
			"ca_cert_file": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_CACERT", ""),
				Description: "Path to a CA certificate file to validate the server's certificate.",
			},
			"ca_cert_dir": {
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_CAPATH", ""),
				Description: "Path to directory containing CA certificate files to " +
					"validate the server's certificate.",
			},
			"client_auth": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Client authentication credentials.",
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"cert_file": {
							Type:     schema.TypeString,
							Required: true,
							DefaultFunc: schema.EnvDefaultFunc(
								"VAULT_CLIENT_CERT",
								"",
							),
							Description: "Path to a file containing the client " +
								"certificate.",
						},
						"key_file": {
							Type:     schema.TypeString,
							Required: true,
							DefaultFunc: schema.EnvDefaultFunc(
								"VAULT_CLIENT_KEY",
								"",
							),
							Description: "Path to a file containing the " +
								"private key that the certificate was issued for.",
						},
					},
				},
			},
			"skip_tls_verify": {
				Type:        schema.TypeBool,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("VAULT_SKIP_VERIFY", ""),
				Description: "Set this to true only if the target Vault server is " +
					"an insecure development instance.",
			},
			"max_lease_ttl_seconds": {
				Type:     schema.TypeInt,
				Optional: true,

				// Default is 20min, which is intended to be enough time for
				// a reasonable Terraform run can complete but not
				// significantly longer, so that any leases are revoked shortly
				// after Terraform has finished running.
				DefaultFunc: schema.EnvDefaultFunc("TERRAFORM_VAULT_MAX_TTL", 1200),
				Description: "Maximum TTL for secret leases requested by this provider",
			},
		},
		ConfigureFunc: providerConfigureWithLogger,
		ResourcesMap: map[string]*schema.Resource{
			"vaulted_vault_secret": resourceVaultSecret(),
		},
	}
}

func providerConfigure(logger logger.Logger, d *schema.ResourceData) (interface{}, error) {
	configInstance := api.DefaultConfig()
	configInstance.Address = d.Get("address").(string)

	clientAuthI := d.Get("client_auth").([]interface{})
	if len(clientAuthI) > 1 {
		return nil, fmt.Errorf("client_auth block may appear only once")
	}

	clientAuthCert := ""
	clientAuthKey := ""
	if len(clientAuthI) == 1 {
		clientAuth := clientAuthI[0].(map[string]interface{})
		clientAuthCert = clientAuth["cert_file"].(string)
		clientAuthKey = clientAuth["key_file"].(string)
	}

	err := configInstance.ConfigureTLS(
		&api.TLSConfig{
			CACert:     d.Get("ca_cert_file").(string),
			CAPath:     d.Get("ca_cert_dir").(string),
			Insecure:   d.Get("skip_tls_verify").(bool),
			ClientCert: clientAuthCert,
			ClientKey:  clientAuthKey,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to configure TLS for Vault API: %s", err)
	}

	configInstance.HttpClient.Transport = logging.NewTransport("Vault", configInstance.HttpClient.Transport)

	client, err := api.NewClient(configInstance)
	if err != nil {
		return nil, fmt.Errorf("failed to configure Vault API: %s", err)
	}

	osExecutor := &os.RealOsExecutor{}

	var privateKey *stdRsa.PrivateKey

	rsaSvc := rsa.NewRsaService(osExecutor)

	privateKeyContentTypeless := d.Get("private_key_content")
	switch privateKeyContent := privateKeyContentTypeless.(type) {
	case string:
		if privateKeyContent != "" {
			fd, err := osExecutor.TempFile("", "vaulted-private-key-from-content")
			if err != nil {
				return nil, fmt.Errorf("failed to create temporary file for vaulted private key from content: %s", err)
			}

			_, err = fd.WriteString(privateKeyContent)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to write private key content to temporary file for vaulted private key: %s",
					err,
				)
			}

			err = fd.Sync()
			if err != nil {
				return nil, fmt.Errorf(
					"failed to sync private key content to temporary file for vaulted private key: %s",
					err,
				)
			}

			err = fd.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to close temporary file for vaulted private key from content: %s", err)
			}

			key, readErr := rsaSvc.ReadPrivateKeyFromPath(fd.Name())
			if readErr != nil {
				return nil, readErr
			}

			privateKey = key

			// NOTE: Clean up the private key from the disk
			err = osExecutor.Remove(fd.Name())
			if err != nil {
				return nil, fmt.Errorf("failed to remove temporary file for vaulted private key from content: %s", err)
			}
		}
	default:
		// NOTE: Do nothing, try with `private_key_path`.
	}

	if privateKey == nil {
		privateKeyPathTypeless := d.Get("private_key_path")
		switch privateKeyPath := privateKeyPathTypeless.(type) {
		case string:
			if privateKeyPath != "" {
				key, readErr := rsaSvc.ReadPrivateKeyFromPath(privateKeyPath)
				if readErr != nil {
					return nil, fmt.Errorf("failed to read private key from path %s, err: %s", privateKeyPath, readErr)
				}

				privateKey = key
			}
		default:
			return nil, fmt.Errorf("non-string private_key_path. actual: %#v", privateKeyPath)
		}
	}

	// In order to enforce our relatively-short lease TTL, we derive a
	// temporary child token that inherits all of the policies of the
	// token we were given but expires after max_lease_ttl_seconds.
	//
	// The intent here is that Terraform will need to re-fetch any
	// secrets on each run and so we limit the exposure risk of secrets
	// that end up stored in the Terraform state, assuming that they are
	// credentials that Vault is able to revoke.
	//
	// Caution is still required with state files since not all secrets
	// can explicitly be revoked, and this limited scope won't apply to
	// any secrets that are *written* by Terraform to Vault.
	token, err := providerToken(d)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, errors.New("no vault token found")
	}

	client.SetToken(token)
	renewable := false
	childTokenLease, err := client.Auth().Token().Create(
		&api.TokenCreateRequest{
			DisplayName: "terraform",
			TTL: fmt.Sprintf(
				"%ds",
				d.Get("max_lease_ttl_seconds").(int),
			),
			ExplicitMaxTTL: fmt.Sprintf(
				"%ds",
				d.Get("max_lease_ttl_seconds").(int),
			),
			Renewable: &renewable,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create limited child token: %s", err)
	}

	log.Printf(
		"[INFO] Using Vault token with the following policies: %s",
		strings.Join(
			childTokenLease.Auth.Policies,
			", ",
		),
	)

	client.SetToken(childTokenLease.Auth.ClientToken)

	return vault.NewClient(logger, client, privateKey), nil
}

func providerToken(d *schema.ResourceData) (string, error) {
	if token := d.Get("token").(string); token != "" {
		return token, nil
	}
	// NOTE: Use ~/.vault-token, or the configured token helper.
	tokenHelper, err := config.DefaultTokenHelper()
	if err != nil {
		return "", fmt.Errorf("error getting token helper: %s", err)
	}
	token, err := tokenHelper.Get()
	if err != nil {
		return "", fmt.Errorf("error getting token: %s", err)
	}
	return strings.TrimSpace(token), nil
}
