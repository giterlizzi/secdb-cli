// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"fmt"
	"io"
)

func renderJSON(w io.Writer, data interface{}) error {
	pretty, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON encode: %w", err)
	}
	_, err = fmt.Fprintln(w, string(pretty))
	return err
}
