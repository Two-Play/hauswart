package api

import (
	"reflect"
	"strings"
	"testing"
)

func TestSchemaSeesFields(t *testing.T) {
	first := Schema()
	if len(first) != 16 {
		t.Fatalf("schema %q", first)
	}
	var b strings.Builder
	describe(&b, specs[TaskPolicySet].payload, map[reflect.Type]bool{})
	if !strings.Contains(b.String(), "daily_minutes:int") || !strings.Contains(b.String(), "wifi:[]{ssid:string") {
		t.Fatalf("the policy is not described in full: %s", b.String())
	}
}
