# Security assessment — `getkin/kin-openapi`

**Target:** `getkin/kin-openapi` @ commit `88aa64c7cb` (server-type library)
**Date:** 2026-07-27
**Method:** Adversarial review seeded from the repository's own fix history, then open hunting. Every finding was traced attacker-input → sink in the current source, verified by an independent skeptic panel (majority-REAL required), and **reproduced with a runnable test** (live panic / measured blow-up). Repro tests were removed afterward; the working tree is unchanged.

**Result: 7 confirmed, exploitable findings.** 1 candidate was rejected on review.

The findings cluster in the **deepObject / array query-parameter decoders** in `openapi3filter/req_resp_decoder.go`: the recent hardening (see GHSAs below) landed on the request-body, multipart, and header decoders but **skipped the query-parameter decoders**, leaving several exact-sibling holes open.

---

## GHSA cross-reference (checked against <https://github.com/getkin/kin-openapi/security>)

Published advisories for this repo and how the current tree relates:

| GHSA | Title (abridged) | Sev | Status in this tree |
|---|---|---|---|
| GHSA-r277-6w6q-xmqw | `ValidationHandler.Load()` fail-open auth bypass (Noop default) | Critical | **Fixed** (verified: no Noop default; fails closed with `ErrAuthenticationServiceMissing`) |
| GHSA-fh4f-47mf-f2gj | Router panic on non-canonical/unsupported HTTP method | Moderate | **Fixed** (`GetOperation` → nil → `ErrMethodNotAllowed`) |
| GHSA-jpcw-4wr7-c3vq | nil-panic: `content` parameter media type with no schema | Moderate | **Fixed** (`mt.Schema == nil` guard present) |
| GHSA-mh7x-f8wq-4jhx | loader panic on self-referential `additionalProperties` `$ref` | Moderate | **Fixed** (returns unresolved-ref error) — but see **F5** (sibling loader nil-panic still open) |
| GHSA-mmfr-pmjx-hw9w | nil-panic in `ConvertErrors` on malformed multipart | High | **Fixed** (`convertParseError` nil-param guard present) |
| GHSA-wq9g-9vfc-cfq9 / CVE-2025-30153 | Data amplification (compressed data) | High | Out of scope of this review (zip decoder is opt-in, already documented) |
| **GHSA-p6wj-qrr4-pgh5** | nil-panic: OpenAPI 3.1 `array` schema missing `items` | **High** | **Fix is INCOMPLETE** → **F1, F2** (query / deepObject paths never guarded) |
| **GHSA-xhj3-7xw9-vr34** | uncontrolled resource consumption in deepObject query decoding | **High** | **Fix is INCOMPLETE** → **F4** (no aggregate cap); **F7** (distinct CPU mechanism) |

**Bottom line:** two already-published *High* advisories are only **partially fixed** in the current tree (F1/F2 re-open GHSA-p6wj on the query surface; F4 re-opens GHSA-xhj3 via a different amplification). F3, F5, F6, F7 are **novel** — no published advisory describes them.

---

## F1 — Query-param `array` without `items` → nil-pointer panic (DoS)

- **class:** input_validation / nil-pointer-dereference (CWE-476)
- **severity:** medium — remote, unauthenticated, single-request panic
- **sink:** `openapi3filter/req_resp_decoder.go:605` (`parseValue`: `schema.Value.AllOf` on a nil `schema`)
- **entry_point:** query string → `ValidateRequest` → `ValidateParameter` (`validate_request.go:181`)
- **missing_guard:** `urlValuesDecoder.parseArray` (`:580`) calls `parseValue(v, schemaRef.Value.Items)` with no nil check. The GHSA-p6wj-qrr4-pgh5 fix added this guard to the standalone `parseArray` (`:1143`), `UrlencodedBodyDecoder` (`:1441`), `MultipartBodyDecoder` (`:1587`), and header decoding — but **not** to this query decoder.
- **taint_path:** `ValidateParameter:181` → `decodeStyledParameter:267` → `decodeValue:344` (`Type.Is("array")`) → `urlValuesDecoder.DecodeArray:569` → `urlValuesDecoder.parseArray:580` → `parseValue(nil):605` → panic
- **exploit:** Spec (OpenAPI 3.1) declares query param `tags` with `schema: {type: array}` (items omitted — legal under 3.1, passes `doc.Validate()`). Attacker sends `GET /q?tags=a&tags=b`. Nil `*SchemaRef` dereferenced → panic.
- **GHSA note:** **Unguarded variant / incomplete fix of `GHSA-p6wj-qrr4-pgh5`** (patched v0.143.0). The advisory explicitly enumerates only urlencoded/multipart/header/`parseArray`; the query-parameter path (`urlValuesDecoder`) was never in scope and remains vulnerable in the patched tree.
- **status:** Reproduced — live panic at `:605` via `:580`.

---

## F2 — deepObject object with `array` property lacking `items` → nil-pointer panic (DoS)

- **class:** input_validation / nil-pointer-dereference (CWE-476)
- **severity:** medium — remote, unauthenticated, single-request panic
- **sink:** `openapi3filter/req_resp_decoder.go:1012` (`buildResObj`: `schema.Value.Type.Is("array")` on a nil `schema`)
- **entry_point:** query string → `ValidateRequest` → `ValidateParameter`
- **missing_guard:** `buildResObj:1028` recurses `buildResObj(..., schema.Value.Items)` with no nil check on `Items` (contrast the guarded standalone `parseArray` at `:1144`). A **distinct** path/sink from F1.
- **taint_path:** `decodeValue:339` (object) → `DecodeObject:722` (deepObject) → `makeObject:947` → `buildResObj:1047` (property `arr`) → `buildResObj:1028` (array branch, nil `Items`) → `buildResObj:1012` → panic
- **exploit:** Spec declares a deepObject query param `obj` with `schema: {type: object, properties: {arr: {type: array}}}` (arr has no items; passes 3.1 `Validate()`). Attacker sends `GET /p?obj[arr][0]=5` (the `[0]` index form makes `deepGet` return a map, reaching the array branch). Panics.
- **GHSA note:** **Second unguarded variant of `GHSA-p6wj-qrr4-pgh5`.** The `buildResObj` deepObject reconstruction path is outside the advisory's stated scope and unpatched.
- **status:** Reproduced — panic at `:1012` via `:1028←:1047←:947←:722`.

---

## F3 — deepObject conflicting scalar/nested keys → `deepSet` type-assertion panic (DoS)

- **class:** input_validation / unchecked-type-assertion (CWE-704) → DoS
- **severity:** medium — remote, unauthenticated, single-request panic
- **sink:** `openapi3filter/req_resp_decoder.go:929` (`deepSet`: `m = m[key].(map[string]any)`, no comma-ok)
- **entry_point:** query string → `ValidateRequest` → `ValidateParameter`, deepObject object param
- **missing_guard:** `deepSet` walks intermediate nodes assuming any existing child is a `map`; `makeObject:945` calls it once per props entry. A scalar key (`"a"` from `filter[a]`) processed before a nested one (`"a\x1Fb"` from `filter[a][b]`) leaves `m["a"]` a `string`, so the assertion panics. No comma-ok, no prefix-collision check.
- **taint_path:** `DecodeObject:722` (deepObject) → `makeObject:945` → `deepSet:929` → panic
- **exploit:** deepObject object param `filter`. Attacker sends `GET /test?filter[a]=1&filter[a][b]=1&filter[c]=1&filter[c][d]=1&filter[e]=1&filter[e][f]=1`. Multiple conflicting pairs defeat Go's randomized map-iteration order → panics on essentially every request. The form-style object decoder is reachable the same way by injecting `%1F` into keys.
- **GHSA note:** **Novel** — no published advisory describes this. It lives in the same deepObject decoder that `GHSA-xhj3-7xw9-vr34` touched, but it is a distinct bug class (panic, not resource exhaustion).
- **status:** Reproduced — `interface conversion: string, not map[string]interface{}` at `:929`.

---

## F4 — deepObject `additionalProperties`-of-arrays → unbounded allocation (OOM DoS) 🔴

- **class:** resource_exhaustion (CWE-770)
- **severity:** high — a single small request exhausts process memory → OOM kill
- **sink:** `openapi3filter/req_resp_decoder.go:1026` (`make([]any, len(arr))`) + `sliceMapToSlice:993-1000`
- **entry_point:** query string → `ValidateRequest` → `ValidateParameter`, deepObject object param
- **missing_guard:** `maxSliceMapToSliceGap` (`:990`) bounds **one** array to +10000 nil holes, but nothing bounds the **number** of arrays. `buildResObj`'s additionalProperties loop (`:1057` `for k := range objectParams`) builds one full-size array per attacker sub-key, each independently passing the per-array gap guard. No aggregate cap on total synthesized slots.
- **taint_path:** `DecodeObject:722` → `makeObject:947` → `buildResObj` additionalProperties `:1057` → per key: `sliceMapToSlice` → `make([]any,10001):1026` → 10001 leaf recursions
- **exploit:** Spec: deepObject param `filter`, schema `{type: object, additionalProperties: {type: array, items: {type: string}}}` (a normal map-of-arrays). Attacker sends `GET /f?filter[k0][10000]=x&filter[k1][10000]=x&…` with N distinct keys. **Measured: N=200 (~4.3 KB query) → 10.6 GB allocated (≈2.6 million× amplification).** A ~1 MB URL (N≈45k, within default `MaxHeaderBytes`) → tens of GB → OOM.
- **GHSA note:** **Incomplete fix of `GHSA-xhj3-7xw9-vr34`** (patched v0.142.0). That advisory/fix bounded a *single* sparse array (`param[items][50000000]=x` → 6.1 GiB). This variant re-achieves the same DoS by multiplying many independently-legal arrays; the per-array bound is present but the **aggregate** bound the advisory implies is missing.
- **status:** Reproduced — 4.3 KB query allocated 10.6 GB.

---

## F5 — `null` example object in a document → nil-pointer panic at load (DoS)

- **class:** input_validation / nil-pointer-dereference (CWE-476)
- **severity:** medium — DoS of any app that loads untrusted OpenAPI documents (panic **before** `Validate()`)
- **sink:** `openapi3/loader.go:1283` (`resolveExampleRef` dereferences `component.Ref` on a nil component)
- **entry_point:** `Loader.LoadFromData` / `LoadFromFile` / `LoadFromURI` on an attacker-supplied document (`loader.go:188`)
- **missing_guard:** `resolveExampleRef` is the **only** `resolveXRef` that does not start with `if component.isEmpty() { return … }` (and `isEmpty` safely handles a nil receiver). Every sibling — `resolveHeaderRef`, `resolveParameterRef`, `resolveRequestBodyRef`, `resolveResponseRef`, `resolveSchemaRef`, `resolveSecuritySchemeRef`, `resolveCallbackRef`, `resolveLinkRef` — has the guard.
- **taint_path:** `LoadFromData:196` → `ResolveRefsIn:286` → `resolveExampleRef:1283` (nil `component`) → panic
- **exploit:** A spec containing `components: {examples: {x: null}}` (or a parameter/header/mediaType `examples: {x: null}`) panics the process during load, before `Validate()` runs.
- **GHSA note:** **Novel**, same family as `GHSA-mh7x-f8wq-4jhx` (loader nil-panic on a crafted spec) but a different trigger and function. The `mh7x` fix addressed self-referential `additionalProperties` `$ref`; the missing `isEmpty` guard on `resolveExampleRef` is not covered by any published advisory.
- **status:** Reproduced — panic at `loader.go:1283` via `:286←:196`.

---

## F6 — Cyclic callback → unbounded recursion / stack overflow in `InternalizeRefs`

- **class:** resource_exhaustion / uncontrolled-recursion (CWE-674)
- **severity:** medium — fatal stack-overflow crash; **gated** on the app calling the opt-in `InternalizeRefs` API
- **sink:** `openapi3/internalize_refs.go:480` (`derefPaths` recursion through `op.Callbacks`; function defined at `:454`)
- **entry_point:** `T.InternalizeRefs` (`internalize_refs.go:505`) on a document built from attacker-controlled data
- **missing_guard:** `visited.go` tracks only `*Schema` (`isVisitedSchema`) and `*Header` (`isVisitedHeader`). `derefPaths`/`derefContent` recursion through `*Callback` / `*PathItem` has **no** visited-set, so a callback `$ref` cycle recurses without bound.
- **taint_path:** `InternalizeRefs:505` → `derefPaths:454` → `op.Callbacks` loop → `derefPaths:480` (cycle) → stack overflow
- **exploit:** Spec whose `components.callbacks.Loop` contains an operation with callback `$ref: '#/components/callbacks/Loop'`. Loads fine; when the app calls `doc.InternalizeRefs(ctx, nil)` (bundling/tooling), the process dies with `fatal error: stack overflow`.
- **GHSA note:** **Novel** — no published advisory covers `InternalizeRefs` recursion. Related to the general recursion-hardening in the loader’s `resolveXRef` chain (which *is* cycle-guarded), but `InternalizeRefs` is a separate traversal that only guards schemas and headers.
- **status:** Reproduced — `fatal error: stack overflow` in `T.derefPaths` at `:480`.

---

## F7 — deepObject decode recompiles a loop-invariant regexp per query key (CPU amplification)

- **class:** resource_exhaustion / inefficiency (CWE-770; not ReDoS — the pattern is fixed)
- **severity:** low — CPU amplification; needs concurrency to saturate cores
- **sink:** `openapi3filter/req_resp_decoder.go:690` — `regexp.MustCompile(fmt.Sprintf(`^%s\[`, …))` inside the `for key, values := range params` loop (`:689`)
- **entry_point:** query string → `ValidateRequest` → `ValidateParameter`, any deepObject object param
- **missing_guard:** the compiled pattern depends only on `param` (spec-defined name), so it is loop-invariant and should be hoisted (like the package-level `deepObjectBracketRE` at `:41`). Instead it is recompiled once per query key; key count is unbounded and attacker-controlled.
- **taint_path:** `DecodeObject:663` (deepObject) → `propsFn` loop `:689` → `MustCompile:690` recompiled N times
- **exploit:** Any endpoint with ≥1 deepObject object param. Attacker sends N junk query keys. **Measured: 20,000 keys → 137 ms CPU/request** (linear, ~7 µs/key). ~100k keys (~1 MB URL) ≈ 0.7 s CPU per deepObject param per request; a few concurrent requests saturate all cores.
- **GHSA note:** **Novel mechanism**, adjacent to `GHSA-xhj3-7xw9-vr34` ("uncontrolled resource consumption in deepObject query decoding"). That advisory addressed memory via `sliceMapToSlice`; this is a *CPU* issue via per-key regex compilation and is not described there.
- **status:** Reproduced — 1k keys → 9 ms; 20k keys → 137 ms.

---

## Ruled out (well-argued negatives)

- **Info disclosure via `SchemaError.Reason` on the OpenAPI 3.1 JSON-Schema-2020 path** (`schema_jsonschema_validator.go:180`). The santhosh-tekuri validator embeds the failing value into `Reason`, seemingly re-opening `fp_5c0555e412`. Rejected 2/3: the only value reflected is **the attacker's own request input**, echoed back to that same attacker — no cross-tenant/secret disclosure. Real invariant gap, negligible security impact.
- **Auth invariant holds.** `validateSecurityRequirement` fails closed with `ErrAuthenticationServiceMissing` when `AuthenticationFunc == nil` (`validate_request.go:437-439`). GHSA-r277 is fully fixed.
- **Loader `$ref` cycle detection is comprehensive.** Every `resolveXRef` uses `shouldVisitRef`/`visitRef`/`unvisitRef`. The only recursion gap is the separate `InternalizeRefs` traversal → **F6**.
- **Router method dispatch** (`GetOperation`/gorillamux) is correctly guarded; `SetOperation`'s panic is load-time only (GHSA-fh4f fixed).

---

## Suggested fixes (each is small)

| # | Fix |
|---|---|
| F1 | Guard `schemaRef.Value.Items == nil \|\| .Value == nil` in `urlValuesDecoder.parseArray` (`:580`) before `parseValue`, returning a `ParseError` (mirror the standalone `parseArray:1144`). |
| F2 | Same nil-`Items` guard before the `buildResObj` array recursion (`:1028`). |
| F3 | Use comma-ok on the `deepSet` assertion (`:929`); on mismatch return a `ParseError` (prefix bound to both scalar and object). |
| F4 | Add an aggregate cap across all `sliceMapToSlice` / array reconstructions per request (total synthesized slots), not just the per-array gap. |
| F5 | Prefix `resolveExampleRef` with the `if component.isEmpty() { return … }` guard its siblings have. |
| F6 | Add `isVisitedCallback` / `isVisitedPathItem` tracking (like `isVisitedSchema`) in `visited.go` and check it in `derefPaths`. |
| F7 | Hoist `regexp.MustCompile` out of the per-key loop (compile once per `param`). |

Recommended order: **F4** (highest impact — OOM), then the query-decoder panic cluster **F1/F2/F3** (same file, one focused change), then loader **F5/F6**, then **F7**.

_All findings are reported, not patched — the working tree is unchanged._
