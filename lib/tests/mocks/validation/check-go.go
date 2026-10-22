//go:build ignore

// Run from an OpenTDF Go SDK module to verify the manifest corpus.
package main

import (
	"archive/zip"
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
		Name     string          `json:"name"`
		Manifest json.RawMessage `json:"manifest"`
		Valid    bool            `json:"valid"`
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		panic(err)
	}
	for _, c := range cases {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		f, err := w.CreateHeader(&zip.FileHeader{Name: "0.manifest.json", Method: zip.Store})
		if err != nil {
			panic(err)
		}
		if _, err := f.Write(c.Manifest); err != nil {
			panic(err)
		}
		if err := w.Close(); err != nil {
			panic(err)
		}
		valid, err := sdk.IsValidTdf(bytes.NewReader(buf.Bytes()))
		if valid != c.Valid {
			panic(fmt.Sprintf("%s: Go returned valid=%t err=%v; expected %t", c.Name, valid, err, c.Valid))
		}
	}
	fmt.Printf("Go IsValidTdf: %d/%d manifest cases matched\n", len(cases), len(cases))
}
