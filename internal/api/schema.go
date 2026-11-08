package api

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"
)

// Schema stands for every task type and the fields of its payload. Two
// programs with the same schema read the same tasks, whatever their version
// number says: hauswart-admin signs only what it knows, so one that is older
// than the server cannot sign what the server came to know since.
var Schema = sync.OnceValue(func() string {
	types := make([]string, 0, len(specs))
	for name := range specs {
		types = append(types, name)
	}
	slices.Sort(types)
	var b strings.Builder
	for _, name := range types {
		b.WriteString(name)
		b.WriteByte('=')
		describe(&b, specs[name].payload, map[reflect.Type]bool{})
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
})

var timeType = reflect.TypeFor[time.Time]()

// describe writes the shape of a type as JSON sees it.
func describe(b *strings.Builder, t reflect.Type, seen map[reflect.Type]bool) {
	if t == nil {
		b.WriteString("nil")
		return
	}
	switch {
	case t == timeType:
		b.WriteString("time")
		return
	case t.Kind() == reflect.Pointer:
		describe(b, t.Elem(), seen)
		return
	case t.Kind() == reflect.Slice || t.Kind() == reflect.Array:
		b.WriteString("[]")
		describe(b, t.Elem(), seen)
		return
	case t.Kind() == reflect.Map:
		b.WriteString("map[")
		describe(b, t.Key(), seen)
		b.WriteString("]")
		describe(b, t.Elem(), seen)
		return
	case t.Kind() != reflect.Struct:
		b.WriteString(t.Kind().String())
		return
	}
	if seen[t] {
		b.WriteString("...")
		return
	}
	seen[t] = true
	defer delete(seen, t)
	b.WriteByte('{')
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if f.Anonymous && name == "" {
			describe(b, f.Type, seen)
			continue
		}
		if name == "" {
			name = f.Name
		}
		b.WriteString(name)
		b.WriteByte(':')
		describe(b, f.Type, seen)
		b.WriteByte(';')
	}
	b.WriteByte('}')
}
