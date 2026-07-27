package openapi3filter_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

const specDeepObjectArrayProp = `
openapi: 3.1.0
info: {title: PoC, version: 1.0.0}
paths:
  /p:
    get:
      parameters:
        - name: obj
          in: query
          style: deepObject
          explode: true
          schema:
            type: object
            properties:
              arr: {type: array}
      responses:
        '200': {description: ok}
`

// TestPoCDeepObjectArrayPropertyPanic fails on vulnerable code: one
// unauthenticated GET request panics the request goroutine.
func TestPoCDeepObjectArrayPropertyPanic(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(specDeepObjectArrayProp))
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

	req, _ := http.NewRequest(http.MethodGet, "/p?obj[arr][0]=5", nil)
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
	t.Log("no panic: code appears patched")
}
