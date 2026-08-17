// SPDX-License-Identifier: Apache-2.0

package output

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

func renderYAML(w io.Writer, data interface{}) error {
	out, err := yaml.Marshal(data)
	if err != nil {
		return fmt.Errorf("YAML encode: %w", err)
	}
	_, err = w.Write(out)
	return err
}
