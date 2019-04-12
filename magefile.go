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

// +build mage

package main

import (
	"fmt"
	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"log"
	"net/http"
	"time"
)

const (
	dockerVaultTestContainerName = "tf_vaulted_test_container"
	dockerVaultRootToken         = "myroot"
)

var (
	vaultStableImageVersions = []string{
		"0.9.6",
		"0.11.6",
		"1.0.3",
		"1.1.0",
	}
	vaultExperimentalImageVersions = []string{"latest"}
)

func Test() {
	// NOTE: Intentionally run sequentially
	mg.Deps(testsAgainstStableVault)
	mg.Deps(testsAgainstExperimentalVault)
}

func testsAgainstStableVault() error {
	for _, imageVersion := range vaultStableImageVersions {
		err := runTestAgainstVault(imageVersion)
		if err != nil {
			return err
		}
	}

	return nil
}

func testsAgainstExperimentalVault() error {
	for _, imageVersion := range vaultExperimentalImageVersions {
		err := runTestAgainstVault(imageVersion)
		if err != nil {
			log.Printf(
				"[WARN] Integration test against experimental Vault %s failed. Reason: %s\n",
				imageVersion,
				err,
			)
		}
	}

	return nil
}

func runTestAgainstVault(imageVersion string) error {
	// NOTE: Ignore error since we clean optimistically
	sh.Run("docker", "rm", "-fv", "tf_vaulted_test_container")

	err := sh.Run(
		"docker",
		"run",
		"-p",
		"8200:8200",
		fmt.Sprintf("--name=%s", dockerVaultTestContainerName),
		"-d",
		"--rm",
		"-ti",
		"-e",
		"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
		"-e",
		fmt.Sprintf("VAULT_DEV_ROOT_TOKEN_ID=%s", dockerVaultRootToken),
		fmt.Sprintf("vault:%s", imageVersion),
	)
	if err != nil {
		return err
	}

	// NOTE: Check 15 times with interval 1 second,
	// for healthiness of previously started Vault.
	isHealthy := false

	log.Printf("Waiting for Vault %s to be healthy\n", imageVersion)
	for i := 0; i < 15; i++ {
		if isVaultHealthy() {
			isHealthy = true
			break
		}
		time.Sleep(1 * time.Second)
	}

	if !isHealthy {
		return fmt.Errorf("Vault %s still not healthy after 15 attempts\n", imageVersion)
	}

	log.Printf("Vault %s is healthy. Proceeding with test plan\n", imageVersion)

	args := []string{"test", "./...", "-cover"}
	if mg.Verbose() {
		args = append(args, "-v")
	}

	err = sh.RunWith(
		map[string]string{
			"VAULT_TOKEN": dockerVaultRootToken,
			"VAULT_ADDR":  "http://localhost:8200",
		},
		"go",
		args...,
	)

	if err != nil {
		return err
	}

	sh.Run("docker", "rm", "-fv", dockerVaultTestContainerName)
	return nil
}

func Lint() error {
	return sh.Run("golangci-lint", "run")
}

func UnitTests() error {
	args := []string{"test", "./...", "-cover", "-short"}
	if mg.Verbose() {
		args = append(args, "-v")
	}

	return sh.Run("go", args...)
}

func isVaultHealthy() bool {
	// NOTE: Wait for healthiness
	// ref: https://www.vaultproject.io/api/system/health.html#read-health-information
	resp, err := http.Get("http://localhost:8200/v1/sys/health")
	if err != nil {
		return false
	}

	return resp.StatusCode == 200
}
