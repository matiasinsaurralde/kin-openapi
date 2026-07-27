package openapi3_test

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

const specNullExample = `
openapi: 3.0.0
info: {title: PoC, version: 1.0.0}
paths: {}
components:
  examples:
    x: null
`

// TestPoCNullExampleLoaderPanic fails on vulnerable code: loading an
// untrusted document that contains a null example panics before Validate().
func TestPoCNullExampleLoaderPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VULNERABLE: loading panicked: %v", r)
		}
	}()
	loader := openapi3.NewLoader()
	_, _ = loader.LoadFromData([]byte(specNullExample))
	t.Log("no panic: code appears patched")
}
