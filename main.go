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

package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
	"github.com/sumup-oss/go-pkgs/logger"

	"github.com/sumup-oss/terraform-provider-vaulted/internal/provider"
)

// these will be set by the goreleaser configuration
// to appropriate values for the compiled binary.
var version = "dev" // goreleaser can also pass the specific commit if you want
// commit  string = ""

func main() {
	var debugMode bool

	flag.BoolVar(
		&debugMode,
		"debug",
		false,
		"set to true to run the provider with support for debuggers like delve",
	)
	flag.Parse()

	loggerInstance := logger.NewLogrusLogger()
	loggerInstance.SetLevel(logger.InfoLevel)

	opts := &plugin.ServeOpts{ProviderFunc: provider.New(loggerInstance, version)}

	if debugMode {
		err := plugin.Debug(context.Background(), "registry.terraform.io/sumup-oss/vaulted", opts)
		if err != nil {
			log.Fatal(err.Error())
		}

		return
	}

	plugin.Serve(opts)
}
