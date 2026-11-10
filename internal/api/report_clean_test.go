package api

import (
	"fmt"
	"testing"
)

func TestReportCleanSessions(t *testing.T) {
	r := Report{Sessions: []LoginSession{{User: "anna"}, {User: "Bad\x1bName"}, {User: "anna", Active: true}, {User: ""}}}
	for i := range 30 {
		r.Sessions = append(r.Sessions, LoginSession{User: fmt.Sprintf("user%d", i)})
	}
	r.Clean()
	if len(r.Sessions) != MaxReportSessions || r.Sessions[0] != (LoginSession{User: "anna", Active: true}) || r.Sessions[1].User != "user0" {
		t.Fatalf("got %+v", r.Sessions)
	}
}
