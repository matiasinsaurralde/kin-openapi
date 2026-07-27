package openapi3filter_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

const specDeepObjectConflict = `
openapi: 3.1.0
info: {title: PoC, version: 1.0.0}
paths:
  /test:
    get:
      parameters:
        - name: filter
          in: query
          style: deepObject
          explode: true
          schema:
            type: object
            additionalProperties: true
      responses:
        '200': {description: ok}
`

// TestPoCDeepObjectKeyCollisionPanic fails on vulnerable code: a single
// unauthenticated GET request panics via an unchecked type assertion.
// Multiple conflicting scalar/nested key pairs defeat Go's randomized map
// order so the panic is essentially deterministic.
func TestPoCDeepObjectKeyCollisionPanic(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(specDeepObjectConflict))
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

	const target = "/test?filter[a]=1&filter[a][b]=1&filter[c]=1&filter[c][d]=1&filter[e]=1&filter[e][f]=1"
	req, _ := http.NewRequest(http.MethodGet, target, nil)
	route, pathParams, err := router.FindRoute(req)
	if err != nil {
		t.Fatalf("route: %v", err)
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VULNERABLE: request handling panicked: %v", r)
		}
	}()
	_ = openapi3filter.ValidateRequest(context.Background(), &openapi3filter.RequestValidationInput{
		Request: req, PathParams: pathParams, Route: route,
		Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
	})
	t.Log("no panic this run: re-run; code appears patched if consistently green")
}
