//go:build ignore

// Run from an OpenTDF Go SDK module to verify the archive corpus.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	sdk "github.com/opentdf/platform/sdk"
)

func main() {
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var cases []struct {
		Name  string `json:"name"`
		Bytes []byte `json:"bytes"`
		Valid bool   `json:"valid"`
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		panic(err)
	}
	for _, c := range cases {
		valid, err := sdk.IsValidTdf(bytes.NewReader(c.Bytes))
		if valid != c.Valid {
			panic(fmt.Sprintf("%s: Go returned valid=%t err=%v; expected %t", c.Name, valid, err, c.Valid))
		}
	}
	fmt.Printf("Go IsValidTdf: %d/%d archive cases matched\n", len(cases), len(cases))
}
