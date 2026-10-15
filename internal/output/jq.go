// SPDX-License-Identifier: Apache-2.0

package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/itchyny/gojq"
)

// JQ is a compiled --jq expression, applied to the -o json output.
//
// It runs without the environment: env and $ENV are empty (gojq only fills
// them with an environment loader, which is not set), so an expression copied
// from someone else can't print SECDB_API_KEY. input/inputs are rejected when
// compiling.
type JQ struct {
	code *gojq.Code
}

// ParseJQ compiles expr, so a syntax error fails before any API call.
func ParseJQ(expr string) (*JQ, error) {
	query, err := gojq.Parse(expr)
	if err != nil {
		return nil, fmt.Errorf("invalid --jq expression: %w", err)
	}
	code, err := gojq.Compile(query)
	if err != nil {
		return nil, fmt.Errorf("invalid --jq expression: %w", err)
	}
	return &JQ{code: code}, nil
}

// write runs the expression on data (the JSON value of the output, see
// jsonValue) and writes each result on its own line: a string as is, without
// quotes (so ".hits[].id" gives one id per line), anything else as indented
// JSON.
func (q *JQ) write(w io.Writer, data any) error {
	iter := q.code.Run(data)
	for {
		v, ok := iter.Next()
		if !ok {
			return nil
		}
		if err, ok := v.(error); ok {
			// halt stops the expression without an error.
			if halt, ok := errors.AsType[*gojq.HaltError](err); ok && halt.Value() == nil {
				return nil
			}
			return fmt.Errorf("--jq: %w", err)
		}
		if err := writeJQValue(w, v); err != nil {
			return err
		}
	}
}

func writeJQValue(w io.Writer, v any) error {
	if s, ok := v.(string); ok {
		_, err := fmt.Fprintln(w, s)
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("--jq: JSON encode: %w", err)
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}
