package httpapi

import (
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRoutesMatchOpenAPISpec keeps api/openapi.yaml honest: every route
// must be documented and every documented operation must exist (ADR-0002).
func TestRoutesMatchOpenAPISpec(t *testing.T) {
	raw, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Servers []struct{ URL string } `yaml:"servers"`
		Paths   map[string]map[string]struct {
			Security *[]map[string][]string `yaml:"security"`
		} `yaml:"paths"`
	}
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	if len(spec.Servers) != 1 {
		t.Fatal("spec must have exactly one server")
	}
	prefix := spec.Servers[0].URL

	documented := map[string]bool{}
	for path, ops := range spec.Paths {
		for method := range ops {
			documented[strings.ToUpper(method)+" "+prefix+path] = true
		}
	}
	srv := New(Deps{})
	for _, rt := range srv.routes {
		key := rt.method + " " + rt.path
		if !documented[key] {
			t.Errorf("route %s is not in api/openapi.yaml", key)
			continue
		}
		delete(documented, key)

		op := spec.Paths[strings.TrimPrefix(rt.path, prefix)][strings.ToLower(rt.method)]
		isPublicInSpec := op.Security != nil && len(*op.Security) == 0
		if (rt.access == public) != isPublicInSpec {
			t.Errorf("%s: public=%v in code but security in spec says public=%v", key, rt.access == public, isPublicInSpec)
		}
		needsCSRF := rt.access != public && !isSafeMethod(rt.method)
		hasCSRF := op.Security != nil && slices.ContainsFunc(*op.Security, func(req map[string][]string) bool {
			_, ok := req["csrfHeader"]
			return ok
		})
		if needsCSRF != hasCSRF {
			t.Errorf("%s: CSRF header required=%v in code, documented=%v", key, needsCSRF, hasCSRF)
		}
	}
	for key := range documented {
		t.Errorf("api/openapi.yaml documents %s but no such route exists", key)
	}
}
