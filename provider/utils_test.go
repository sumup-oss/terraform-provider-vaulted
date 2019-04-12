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
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestTrimStringStateFunc(t *testing.T) {
	t.Run(
		"with non-string input, it panics",
		func(t *testing.T) {
			t.Parallel()

			valueArg := 1

			assert.Panics(
				t,
				func() {
					trimStringStateFunc(valueArg)
				},
			)
		},
	)

	t.Run(
		"with string input containing leading and trailing spaces, it returns input without spaces",
		func(t *testing.T) {
			t.Parallel()

			valueArg := "\t 12345    "

			actualReturn := trimStringStateFunc(valueArg)
			assert.Equal(t, "12345", actualReturn)
		},
	)

	t.Run(
		"with string input containing spaces as part of value, it returns input with spaces",
		func(t *testing.T) {
			t.Parallel()

			valueArg := "1 2 3 4 5"

			actualReturn := trimStringStateFunc(valueArg)
			assert.Equal(t, "1 2 3 4 5", actualReturn)
		},
	)
}
