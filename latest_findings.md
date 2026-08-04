# kin-openapi — new security findings

**Target:** `github.com/getkin/kin-openapi`, latest `master` (analyzed from first principles; no history/changelog diffing).
**Toolchain:** Go 1.25. **Dependencies audited:** `santhosh-tekuri/jsonschema/v6 v6.0.2`, `oasdiff/yaml3 v0.0.14`, `gorilla/mux v1.8.0`, `oasdiff/yaml v0.1.1`, `go-openapi/jsonpointer`.
**Method:** multi-round, multi-agent portfolio search (3 rounds, 6→6→4 approach families) with adversarial 2-skeptic verification; **every finding below was independently reproduced** with a runnable Go test against the current tree. Findings are new — distinct from prior work in this repo and from all published advisories at <https://github.com/getkin/kin-openapi/security> (GHSA-mh7x-f8wq-4jhx, -fh4f-47mf-f2gj, -jpcw-4wr7-c3vq, -r277-6w6q-xmqw, -p6wj-qrr4-pgh5, -xhj3-7xw9-vr34, -mmfr-pmjx-hw9w, -wq9g-9vfc-cfq9, -74vm-87hj-r66f).

Attacker models: **REQ** = a remote client sends an HTTP request to an endpoint validated by `openapi3filter` against a fixed, trusted spec. **DOC** = the application loads/validates an attacker-influenced OpenAPI document.

## Summary

| # | Title | Class | Model | Sev |
|---|---|---|---|---|
| NF-1 | `additionalProperties:false` not enforced for form bodies & object params (mass assignment) | Validation bypass | REQ | Medium (6.5) |
| NF-2 | Concurrent validation races the shared spec `Default` map → fatal crash + spec corruption | Race → DoS | REQ | High (7.0) |
| NF-3 | 3.1 numeric body + oversized exponent → nil `big.Rat` panic in jsonschema v6 | Dep crash | REQ | High (7.5) |
| NF-4 | 3.1 `uniqueItems` array + oversized exponent → nil `big.Rat` panic in `writeHash` | Dep crash | REQ | High (7.5) |
| NF-5 | 3.1 recursive `anyOf`/`oneOf` union → exponential-time validation in jsonschema v6 | Dep CPU DoS | REQ | High (7.5) |
| NF-6 | Tiny `multipleOf` → `big.Rat.Quo` division-by-zero panic (own 3.0 validator) | Crash | REQ | Medium (5.3) |
| NF-7 | `format: int64` range not enforced for JSON bodies (float saturation) | Limits bypass | REQ | Medium (5.3) |
| NF-8 | YAML body with NaN/Inf → panic in `SchemaError.Error()` when the error is rendered | Crash | REQ | Medium (6.5) |
| NF-9 | Legacy router panics on a `/{var}.suffix` request path | Crash | REQ | Medium (5.8) |
| NF-10 | Null server variable → nil deref in `doc.Validate()` | Crash | DOC | Medium (5.0) |

All CVSS are v3.1 base scores; adjust to your deployment.

---

## NF-1 — `additionalProperties: false` silently bypassed for form bodies and object-typed parameters (mass assignment)

### Summary
For `application/x-www-form-urlencoded` request bodies and for object-typed style parameters (query/path/header/cookie), the decoder reconstructs the object **only from schema-declared properties**, silently discarding any field the schema does not declare — *before* schema validation runs. Consequently `additionalProperties: false` is never enforced: undeclared/unexpected fields pass validation. A backend that re-reads the raw request (the raw bytes are preserved) receives the smuggled fields. This is a classic mass-assignment / parameter-pollution bypass. The identical payload sent as `application/json` is correctly rejected, confirming the asymmetry is a bug, not intent.

### Details
`UrlencodedBodyDecoder` (`openapi3filter/req_resp_decoder.go`) builds the object via `decodeSchemaConstructs`, which iterates only `schemaRef.Value.Properties` (and `allOf`/`anyOf`/`oneOf`); it never inspects form keys absent from `Properties`, and has no `AdditionalProperties` handling. The resulting map is validated at `openapi3filter/validate_request.go:364`. `additionalProperties:false` enforcement in `openapi3/schema.go` (`visitJSONObject`) only iterates keys **present** in the decoded map, so a dropped key never triggers `property %q is unsupported`. The object-parameter path has the same shape in `buildResObj` (object branch): unknown props are stripped before `VisitJSON`. (Contrast: `MultipartBodyDecoder` *does* reject undefined parts, and `JSONBodyDecoder` decodes the full map, so both correctly enforce the constraint.)

### PoC
Spec: `POST /p`, `application/x-www-form-urlencoded`, schema `{type: object, additionalProperties: false, required: [role], properties: {role: {type: string, enum: [user]}}}`.
Request: `Content-Type: application/x-www-form-urlencoded`, body `role=user&isAdmin=true&groups[]=admin`.
**Observed:** `ValidateRequest` returns `nil` (PASS). The identical JSON body `{"role":"user","isAdmin":true}` under an `application/json` entry is correctly rejected: `property "isAdmin" is unsupported`.

### Impact
Validation bypass enabling mass assignment / parameter smuggling: undeclared attacker fields survive an `additionalProperties:false` schema meant to strip them, and reach the downstream handler (raw body is preserved). Impact escalates to privilege escalation if the backend binds those fields (e.g. `isAdmin`, `role`).

### Runbook
- **Fix:** in `decodeSchemaConstructs`/`UrlencodedBodyDecoder` and `buildResObj`, when `additionalProperties` is `false`, reject form keys / object properties not present in the schema (or surface them so `VisitJSON` can reject them). Mirror the multipart decoder's undefined-key rejection.
- **Detect:** log requests whose raw form/param key set exceeds the schema's declared properties for `additionalProperties:false` schemas.
- **Mitigate now:** validate form bodies as JSON where possible, or add an application-level allow-list of form keys.

### Severity
Medium **6.5** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`. CWE-915 (mass assignment), CWE-20. Model REQ; precondition: spec declares a form body or object param with `additionalProperties:false` (a security-motivated, common pattern).

---

## NF-2 — Concurrent request validation races the shared spec `Default` map → fatal crash + spec corruption

### Summary
When default-setting is enabled (the default), validating a request body whose object property is omitted **writes the schema's default into the object being validated by aliasing the single shared `Schema.Default` map inside the loaded spec**, and then recurses into that same shared map to fill nested defaults. Under concurrent requests (the normal server case) two goroutines read and write the same shared map, which Go turns into `fatal error: concurrent map read and map write` — an unrecoverable process abort. Independently, the loaded spec is silently, permanently mutated (defaults accumulate into the shared object), corrupting global read-only state.

### Details
`openapi3/schema.go` `visitJSONObject`: for an omitted property with a default, `value[propName] = dflt` (**write, `schema.go:2846`**) where `dflt` is the shared `Schema.Default` object (`Schema.Default` is `any`; an object default unmarshals to one shared `map[string]any`). The second loop recurses `visitJSON(settings, value[p])` into that shared map, and for each nested property with a default writes `sharedMap[nested] = nestedDefault` while another goroutine reads `sharedMap[nested]` (**read, `schema.go:2844`**) or iterates `componentNames(sharedMap)`. Reached via `openapi3filter/validate_request.go:343` (`DefaultsSet`) + `:364` `VisitJSON`, out-of-the-box through the `openapi3filter.Validator` middleware (`SkipSettingDefaults` is false by default).

### PoC
Spec: `POST /accounts`, `application/json`, schema with `page: {type: object, default: {}, properties: {num:{type:integer,default:1}, size:{type:integer,default:10}, order:{type:string,default:"desc"}}}`.
Attack: fire many concurrent `POST /accounts` with body `{}` (omits `page`).
**Observed (`go test -race`):** `WARNING: DATA RACE — Read at schema.go:2844 ... Previous write at schema.go:2846`, in `visitJSONObject`, across goroutines. Without `-race`, a cold-start burst aborts with `fatal error: concurrent map read and map write`. Non-crashing runs leave the shared `page` default map permanently mutated (0 → N keys), proving cross-request corruption of the loaded document.

### Impact
Remote, unauthenticated denial of service: an unrecoverable Go fatal error aborts the whole process (not catchable by `recover`, so no middleware shields it), enabling a crash-loop. Plus silent, persistent corruption of the process-global spec (`*openapi3.T`), which is meant to be read-only after load.

### Runbook
- **Fix:** deep-copy defaults before assigning them into the per-request value (never alias `Schema.Default`); treat the loaded spec as immutable during validation.
- **Detect:** run the service under `-race` in CI with a concurrent-request test; alarm on `fatal error: concurrent map`.
- **Mitigate now:** set `Options.SkipSettingDefaults = true` (disables the write path) if defaults injection is not required.

### Severity
High **7.0** — `AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H` (AC:H reflects the concurrency window + spec-shape precondition). CWE-362, CWE-567, CWE-770. Model REQ; precondition: spec has an object property with an object default whose sub-schema has defaults (an ordinary pattern), default Options.

---

## NF-3 — OpenAPI 3.1 numeric body with an oversized exponent → nil `big.Rat` panic in jsonschema v6

### Summary
For OpenAPI 3.1 specs, kin-openapi auto-enables the `santhosh-tekuri/jsonschema` 2020-12 validator with no opt-in. A request-body number with a base-10 exponent magnitude > 1,000,000 (e.g. `1e1000001`) causes that validator to dereference a nil `*big.Rat` when checking any numeric constraint (`minimum`/`maximum`/`exclusiveMinimum`/`exclusiveMaximum`/`multipleOf`), panicking. An 11-byte value crashes request validation.

### Details
`JSONBodyDecoder` calls `dec.UseNumber()`, preserving the value as `json.Number`. `openapi3filter/validate_request.go:359-364` appends `EnableJSONSchema2020()` (because the spec is 3.1) and calls `VisitJSON`, reaching `openapi3/schema_jsonschema_validator.go` → jsonschema v6 `validator.go:519` `new(big.Rat).SetString(fmt.Sprintf("%v", v))`. On Go 1.25, `SetString` returns `(nil, false)` for `|exponent| > 1e6` instead of expanding; the code discards the ok flag, then `validator.go:525` `num().Cmp(s.Minimum)` dereferences the nil `*big.Rat` → panic (`math/big/rat.go`). (On a Go without that guard the same input balloons `big.Rat` to multi-GB → OOM instead — DoS either way.)

### PoC
Spec: `openapi: 3.1.0`; `POST /p`, `application/json`, schema `{type: object, properties: {n: {type: number, minimum: 0}}}`.
Request: body `{"n": 1e1000001}`.
**Observed:** `ValidateRequest` panics with `runtime error: invalid memory address or nil pointer dereference` inside jsonschema v6 numeric validation.

### Impact
Unauthenticated remote crash of request validation with a tiny payload; process crash where validation runs outside net/http's per-request recover (custom middleware, goroutines, gRPC-gateway, batch).

### Runbook
- **Fix (upstream):** jsonschema v6 must honor the `ok` result of `big.Rat.SetString`. **In kin-openapi:** bound/reject numbers with extreme exponents before handing `json.Number` to the validator, or wrap validation in `recover`.
- **Detect:** alert on panics originating in `.../jsonschema/v6/validator.go`.
- **Mitigate now:** pre-validate/limit request-number magnitude at the edge.

### Severity
High **7.5** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. CWE-476 (in dependency), CWE-20. Model REQ; precondition: OpenAPI 3.1 spec with any numeric constraint (`minimum: 0` suffices — extremely common).

---

## NF-4 — OpenAPI 3.1 `uniqueItems` array with an oversized-exponent element → nil `big.Rat` panic in `writeHash`

### Summary
A distinct nil-`big.Rat` panic in the same validator: an `uniqueItems: true` array containing a number with `|exponent| > 1e6` panics in the hashing path used to detect duplicates. Requires >20 elements so the validator takes the hash branch (≤20 uses a guarded equality path).

### Details
`validator.go:342` (`uniqueItems`) → `duplicates()` (`util.go:342`): arrays >20 elements go to `writeHash` (`util.go:395`) which does `new(big.Rat).SetString(fmt.Sprint(v))` and **discards the ok flag** with `_`, then `util.go:396` `num.Num().Bytes()` dereferences the nil `*big.Rat`. Same 3.1 auto-enable and `json.Number` source as NF-3.

### PoC
Spec: `openapi: 3.1.0`; `POST /p`, `application/json`, schema `{type: array, uniqueItems: true, items: {type: number}}`.
Request: JSON array of 21 distinct integers followed by `1e1000001` (22 elements).
**Observed:** `ValidateRequest` panics with a nil-pointer dereference in `writeHash`.

### Impact
Same DoS profile as NF-3; separate code path requiring its own fix.

### Runbook
- **Fix:** as NF-3, plus `writeHash` must not ignore the `SetString` ok flag.
- **Mitigate now:** cap request array length / number magnitude at the edge; `recover` around validation.

### Severity
High **7.5** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. CWE-476, CWE-20. Model REQ; precondition: 3.1 spec with an `uniqueItems` numeric array.

---

## NF-5 — OpenAPI 3.1 recursive `anyOf`/`oneOf` union → exponential-time validation (CPU DoS)

### Summary
For a 3.1 spec whose request-body schema is a recursive union (`anyOf`/`oneOf` branches that recurse via `$dynamicRef`/`$ref`), jsonschema v6 validates a nested instance without memoization, so a deeply nested body forces ~2^depth evaluations of the shared subtree. A ~400-byte request pins one CPU core for hours-to-forever; a handful of such requests exhaust the worker pool.

### Details
jsonschema v6 `validator.go:579-619` (`anyOf`/`oneOf`) each call `validateSelf` → `validate()` recursively with no result caching; `checkCycle` does not fire because each instance level has a distinct `vid`. A leaf value that fails every branch (e.g. a non-object at the bottom) forces both branches to be explored at every level → exponential. Reached via the standard 3.1 `EnableJSONSchema2020` path; v6 compiles the self-contained `$dynamicRef` schema and runs it (no fallback).

### PoC
Spec: `openapi: 3.1.0`; `POST /x`, `application/json`, schema `{$dynamicAnchor: node, anyOf: [{type: object, required: [next], properties: {next: {$dynamicRef: '#node'}}}, {…same…}]}`.
Request: body `{"next":{"next":…{"next":0}…}}` nested ~20–40 deep (leaf `0`).
**Observed (through `ValidateRequestBody`):** depth 8 → 117 ms, depth 10 → 434 ms, depth 12 → 2.34 s (~4–5× per +2 levels). Depth ~24 ≈ hours; ~40 effectively never returns.

### Impact
Asymmetric remote CPU-exhaustion DoS: a few hundred bytes → unbounded single-core compute; a small number of concurrent requests saturates the server.

### Runbook
- **Fix (upstream):** memoize `(schema,instance-location)` results in the union validators. **In kin-openapi:** cap request-body nesting depth / evaluation budget before/around 3.1 validation.
- **Detect:** per-request validation-time watchdog; alarm on validations exceeding a time budget.
- **Mitigate now:** impose a max body depth at the edge; run validation with a context deadline in a cancelable worker.

### Severity
High **7.5** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. CWE-407, CWE-834. Model REQ; precondition: 3.1 spec whose body schema is a recursive `anyOf`/`oneOf` union (polymorphic/recursive types — comment trees, filter DSLs, ASTs).

---

## NF-6 — Tiny `multipleOf` → `big.Rat.Quo` division-by-zero panic (kin-openapi's own 3.0 validator)

### Summary
kin-openapi's built-in (3.0) number validator formats `multipleOf` through `%.10f` when building a `big.Rat` divisor. A positive but sub-`~4.9e-11` `multipleOf` rounds to `0`, so validating any number against that field calls `big.Rat.Quo(_, 0)`, which panics `division by zero`.

### Details
`openapi3/schema.go:2569` `(&big.Rat{}).Quo(numRat, denRat).IsInt()`, where `denRat` was built from a `%.10f`-formatted `multipleOf` (region `schema.go:2562-2569`). For `multipleOf ≤ ~4.9e-11` the formatted denominator is `0.0000000000` → `denRat == 0` → `Quo` panics.

### PoC
Spec: `POST /x`, `application/json`, schema `{type: object, properties: {n: {type: number, multipleOf: 1e-17}}}`.
Request: body `{"n": 5}`.
**Observed:** `ValidateRequest` panics `division by zero`.

### Impact
Remote crash of request validation for any endpoint whose spec declares a very small `multipleOf` (plausible for crypto/token amounts, high-precision fields).

### Runbook
- **Fix:** build the `big.Rat` divisor from the exact `float64` (`big.Rat.SetFloat64`) instead of a `%.10f` string, and guard `denRat.Sign()==0`.
- **Detect:** static-lint specs for `multipleOf` below the rounding floor.
- **Mitigate now:** reject/normalize such `multipleOf` values at load.

### Severity
Medium **5.3** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L`. CWE-369. Model REQ; precondition: spec declares `multipleOf ≤ ~4.9e-11` (uncommon).

---

## NF-7 — `format: int64` range constraint is a no-op for JSON request bodies (limits bypass)

### Summary
For a `type: integer, format: int64` body field, kin-openapi's own validator checks the range by first casting the JSON number to `int64` and validating *that* — but the cast itself saturates/truncates an out-of-range value into range, so numbers outside int64 bounds are accepted. The declared bound is silently unenforced. (Query/path/header params are unaffected — they parse via `strconv.ParseInt(raw,0,64)`, which rejects out-of-range.)

### Details
`openapi3/schema.go:2407` `f.Validate(int64(value))` where `value` is the decoded float64; `openapi3/schema_formats.go:92` `rangeFormat.Validate` then range-checks the already-saturated `int64`. A value like `1e19` (> max int64) becomes `int64(...)` ≈ `math.MaxInt64` (in range) → passes.

### PoC
Spec: `POST /x`, `application/json`, schema `{type: object, properties: {n: {type: integer, format: int64}}}`.
Request: body `{"n": 10000000000000000000}` (1e19, exceeds int64).
**Observed:** `ValidateRequest` returns `nil` (accepted) — the `int64` bound is not enforced.

### Impact
Declared numeric bound bypass: values outside int64 reach the handler as validated. Downstream integer handling (DB columns, arithmetic, other-language services) can overflow/misbehave on data the API contract said was in range.

### Runbook
- **Fix:** range-check the original number (as `float64`/`json.Number`/`big.Int`) before casting; reject non-integral or out-of-int64 values explicitly.
- **Detect:** contract tests submitting boundary/over-range integers.

### Severity
Medium **5.3** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`. CWE-20, CWE-190 (adjacent). Model REQ; precondition: a body field with `format: int64` (or `int32`, same shape).

---

## NF-8 — YAML request body with NaN/Inf in a collection → panic in `SchemaError.Error()` when the error is rendered

### Summary
The YAML body decoders accept IEEE special floats (`.nan`, `.inf`). When such a value ends up in a failing schema check inside a collection, the resulting `SchemaError.Value` holds NaN/Inf; `(*SchemaError).Error()` JSON-encodes that value and `panic`s if encoding fails (`json` cannot marshal NaN/Inf). Because error encoders and loggers call `Error()`, a validation failure that should yield a clean 4xx instead triggers an uncaught panic.

### Details
`openapi3/schema.go:3128-3129` inside `(*SchemaError).Error()`: `if err := encoder.Encode(err.Value); err != nil { panic(err) }` (also `:3124-3125` for `err.Schema`). A YAML body value containing NaN/Inf in a slice/map becomes `err.Value`; `encoder.Encode` returns `json: unsupported value: NaN`, and the method panics instead of returning a string.

### PoC
Spec: `POST /x`, `application/yaml`, schema `{type: array, maxItems: 1, items: {type: number}}`.
Request: `Content-Type: application/yaml`, body `- .nan\n- .inf\n`.
**Observed:** `ValidateRequest` returns a validation error (maxItems); calling `err.Error()` panics `json: unsupported value: NaN`.

### Impact
Remote crash triggered while rendering/logging a validation error: an endpoint that accepts YAML and whose error-handling calls `err.Error()` (the norm) panics on a crafted body, causing a per-request crash / process crash outside net/http recover, plus a stack-trace log-flood.

### Runbook
- **Fix:** in `SchemaError.Error()`, never `panic` on encode failure — fall back to a safe representation (`fmt.Sprintf("%v", …)` / omit the value). Consider rejecting NaN/Inf at YAML decode.
- **Detect:** fuzz error rendering with NaN/Inf/`map[interface{}]interface{}` values.
- **Mitigate now:** don't register YAML body decoders on untrusted endpoints; sanitize before logging.

### Severity
Medium **6.5** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`. CWE-248, CWE-755. Model REQ; precondition: endpoint accepts `application/yaml`/`x-yaml`, and error text is produced (routine).

---

## NF-9 — Legacy router panics on a `/{var}.suffix` request path

### Summary
The legacy router's `FindRoute` dereferences a nil `node` for a request whose decoded path equals a `{variable}<literal-suffix>` template (e.g. `/{id}.json`, common for extension-based content negotiation). A single request `GET /%7Bid%7D.json` (decodes to `/{id}.json`) crashes routing. gorillamux is unaffected.

### Details
`routers/legacy/router.go:158` `paramKeys := node.VariableNames` executes with `node == nil`. Cause: `pathpattern` compiles `/{id}.json` into a variable node plus a `.json` constant leaf, but `matchRemaining`'s greedy `SuffixKindVariable` consumes the whole `{id}.json` token, leaving nothing for the `.json` constant, so `Match` returns `(nil,nil)`. Because `remainingPath` is the literal template string, `doc.Paths.Value("/{id}.json")` exact-matches the map key and `GetOperation("GET") != nil`, so neither early-return fires and control falls through to the nil `node` deref. (Requires the no-`servers` branch so `remainingPath` is the decoded URL path; a legitimate `/123.json` cleanly 404s.)

### PoC
Spec (no `servers`): `paths: {"/{id}.json": {get: {parameters: [{name: id, in: path, required: true, schema: {type: string}}], responses: {"200": {description: ok}}}}}`. Build `routers/legacy.NewRouter(doc)` (Validate passes).
Request: `GET /%7Bid%7D.json`.
**Observed:** `FindRoute` panics `runtime error: invalid memory address or nil pointer dereference` at `routers/legacy/router.go:158`.

### Impact
Unauthenticated remote crash of routing on the (opt-in but supported) legacy router; per-request crash + stack-log under net/http, full process crash for non-net/http consumers.

### Runbook
- **Fix:** nil-check `node` before `node.VariableNames` in `FindRoute`; return `ErrPathNotFound` for unmatched `{var}<suffix>` templates. (Reconcile the pathpattern Add-vs-Match asymmetry.)
- **Detect:** fuzz `FindRoute` with paths equal to templated keys.
- **Mitigate now:** use the default gorillamux router; avoid `{var}<suffix>` path templates on legacy.

### Severity
Medium **5.8** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L` (non-default router lowers exposure; A:H for non-net/http consumers). CWE-476. Model REQ.

---

## NF-10 — Null server variable → nil deref in `doc.Validate()`

### Summary
Loading and validating a document whose `servers[].variables` contains a variable declared with an explicit null value (and whose name appears in the URL template) panics with a nil-pointer dereference during `doc.Validate()`.

### Details
`openapi3/server.go:302` `if serverVariable.Default == ""` dereferences a nil `*ServerVariable` receiver, reached from `server.go:233` (via `server.go:21`) during server validation.

### PoC
Spec: `servers: [{url: '{scheme}://api.example.com/v1', variables: {scheme: }}]`, one path.
Call: `doc.Validate(context.Background())`.
**Observed:** panic `runtime error: invalid memory address or nil pointer dereference` at `openapi3/server.go:302`.

### Impact
Denial of service for any application that validates untrusted/attacker-influenced OpenAPI documents in-process (spec-processing tools, gateways, SaaS that accept user specs): a crafted spec crashes the load/validate operation.

### Runbook
- **Fix:** nil-check each `*ServerVariable` entry in `Server.Validate` before dereferencing.
- **Detect:** fuzz `doc.Validate` with null component/variable entries.
- **Mitigate now:** wrap untrusted `Validate` calls in `recover`; reject specs with null `variables` entries pre-validation.

### Severity
Medium **5.0** — `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` scaled down for the untrusted-document precondition. CWE-476. Model DOC.

---

## Coverage / approach registry (what was explored)

Three rounds, adversarially verified. **Productive families:** validation-bypass/mass-assignment (NF-1, NF-7), concurrency/shared-state (NF-2), dependency chains into `jsonschema v6` (NF-3, NF-4, NF-5), own-validator numeric edge cases (NF-6), error-rendering panics via `yaml3` values (NF-8), router internals (NF-9), spec-model validation (NF-10).

**Explored and found clean / rejected on verification (documented so they aren't re-run without a new mechanism):** external `$ref` path-traversal & SSRF (blocked by default `IsExternalRefsAllowed=false`; only reachable under an explicit non-default opt-in — by design); authentication/security-requirement bypass (no defect found — fails closed, AND/OR and global-vs-operation precedence handled correctly); case-sensitive/charset media-type matching; `%2F` router path smuggling; per-request 3.1 validator recompilation (perf, not attacker-amplified); YAML billion-laughs (mitigated by the alias cap); parser deep-nesting stack overflow (mitigated by the ~10000 depth cap); hex/octal integer query params; `RegexCompiler` cache; duplicate/nested multipart parts (no measurable blowup in repro); cross-request data bleed and default-after-auth write-back (rejected — no exploitable logic outcome beyond NF-2's crash); non-BMP `maxLength` and `uint64`-count overflow (rejected).

**RCE:** none. There is no runtime command/code-execution sink (no `os/exec`, `plugin.Open`, `unsafe`, CGO, or input-reachable templating on any request or document path), so remote code execution is structurally absent — only the DoS / bypass classes above apply.

*All findings above were reproduced against the current tree with runnable Go tests; the tests were not committed (working tree left clean).*
