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
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sumup-oss/go-pkgs/logger"
	"os"
	"testing"
)

func testProviders(provider terraform.ResourceProvider) map[string]terraform.ResourceProvider {
	return map[string]terraform.ResourceProvider{
		"vaulted": provider.(*schema.Provider),
	}
}

func testAccPreCheck(t *testing.T) {
	for _, v := range []string{"VAULT_ADDR", "VAULT_TOKEN", "VAULT_PRIVATE_KEY_PATH"} {
		envVar := os.Getenv(v)
		if envVar == "" {
			t.Fatalf("%s must be set for acceptance tests\n", v)
		}
	}
}

func TestProvider(t *testing.T) {
	t.Run(
		"it is a valid terraform provider",
		func(t *testing.T) {
			t.Parallel()

			loggerInstance := logger.NewLogrusLogger()
			p := provider(loggerInstance)

			_, ok := p.(terraform.ResourceProvider)
			require.True(t, ok)

			actualErr := p.(*schema.Provider).InternalValidate()
			require.Nil(t, actualErr)
		},
	)

	t.Run(
		"it has resource `vaulted_vault_secret` registered",
		func(t *testing.T) {
			t.Parallel()

			loggerInstance := logger.NewLogrusLogger()
			p := provider(loggerInstance)

			actual := p.Resources()
			assert.Equal(t, 1, len(actual))
			assert.Equal(t, "vaulted_vault_secret", actual[0].Name)
			assert.True(t, actual[0].Importable)
			assert.True(t, actual[0].SchemaAvailable)
		},
	)
}

func TestFuncWithLogger(t *testing.T) {
	t.Parallel()

	loggerInstance := logger.NewLogrusLogger()
	actual := FuncWithLogger(loggerInstance)()
	require.NotNil(t, actual)

	_, ok := actual.(terraform.ResourceProvider)
	require.True(t, ok)
}
