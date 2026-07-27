package openapi3filter_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// These tests cover nil-pointer / type-assertion panics on the styled
// parameter decoding paths (query, deepObject). Like the cases in
// array_items_nil_panic_test.go, they rely on OpenAPI 3.1 legally allowing
// `type: array` without `items` (which passes doc.Validate()), plus a
// deepObject key-structure conflict. The decoders must return a clean
// validation error instead of panicking, so a remote request cannot crash the
// validating goroutine.

func validateGet(t *testing.T, spec, target string) (panicVal any, reqErr error) {
	t.Helper()
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(spec))
	require.NoError(t, err)
	require.NoError(t, doc.Validate(loader.Context))
	router, err := gorillamux.NewRouter(doc)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodGet, target, nil)
	require.NoError(t, err)
	route, pathParams, err := router.FindRoute(req)
	require.NoError(t, err)

	panicVal = catchPanicValue(func() {
		reqErr = openapi3filter.ValidateRequest(context.Background(), &openapi3filter.RequestValidationInput{
			Request: req, PathParams: pathParams, Route: route,
			Options: &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc},
		})
	})
	return panicVal, reqErr
}

// A styled query parameter with `type: array` and no `items` used to panic in
// urlValuesDecoder.parseArray (the standalone parseArray was already guarded,
// but this sibling method was not).
func TestArrayItemsNil_QueryParamNoPanic(t *testing.T) {
	const spec = `
openapi: 3.1.0
info: {title: t, version: 1.0.0}
paths:
  /q:
    get:
      parameters:
        - name: tags
          in: query
          schema: {type: array}
      responses:
        '200': {description: ok}
`
	panicVal, reqErr := validateGet(t, spec, "/q?tags=a")
	require.Nil(t, panicVal, "must not panic")
	require.Error(t, reqErr, "must return a clean error")
	require.Contains(t, reqErr.Error(), "array items")
}

// A deepObject object parameter with an array-typed property lacking `items`
// used to panic in buildResObj's array branch (schema.Value.Items == nil).
func TestArrayItemsNil_DeepObjectPropertyNoPanic(t *testing.T) {
	const spec = `
openapi: 3.1.0
info: {title: t, version: 1.0.0}
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
            properties:
              tags:
                type: array
      responses:
        '200': {description: ok}
`
	panicVal, _ := validateGet(t, spec, "/f?filter[tags][0]=x")
	require.Nil(t, panicVal, "must not panic")
}

// Same buildResObj sink reached through additionalProperties: {type: array}.
func TestArrayItemsNil_DeepObjectAdditionalPropsNoPanic(t *testing.T) {
	const spec = `
openapi: 3.1.0
info: {title: t, version: 1.0.0}
paths:
  /g:
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
      responses:
        '200': {description: ok}
`
	panicVal, _ := validateGet(t, spec, "/g?filter[anything][0]=x")
	require.Nil(t, panicVal, "must not panic")
}

// A deepObject object parameter where a key is used both as a scalar leaf and
// as an object path (filter[a]=v and filter[a][b]=w) used to panic on an
// unchecked type assertion in deepSet. Many conflict pairs in one request make
// the (map-iteration-order dependent) trigger effectively deterministic.
func TestDeepObjectKeyConflictNoPanic(t *testing.T) {
	const spec = `
openapi: 3.1.0
info: {title: t, version: 1.0.0}
paths:
  /d:
    get:
      parameters:
        - name: filter
          in: query
          style: deepObject
          explode: true
          schema: {type: object}
      responses:
        '200': {description: ok}
`
	var q []string
	for i := 0; i < 64; i++ {
		q = append(q, fmt.Sprintf("filter[k%d]=v", i))    // scalar leaf
		q = append(q, fmt.Sprintf("filter[k%d][b]=w", i)) // same key as an object path
	}
	panicVal, _ := validateGet(t, spec, "/d?"+strings.Join(q, "&"))
	require.Nil(t, panicVal, "must not panic on conflicting deepObject keys")
}
