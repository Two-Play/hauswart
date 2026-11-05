package store

import (
	"errors"
	"slices"
	"testing"
)

func TestGroups(t *testing.T) {
	s := open(t)
	device(t, s, "a")
	device(t, s, "b")
	id, err := s.CreateGroup(ctx, "laptops")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateGroup(ctx, "laptops"); !errors.Is(err, ErrGroupExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := s.SetGroupDevices(ctx, id, []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetGroupDevices(ctx, id, []string{"a", "unknown"}); err == nil {
		t.Fatal("accepted an unknown device")
	}
	members, err := s.GroupDevices(ctx, id)
	if err != nil || !slices.Equal(members, []string{"a", "b"}) {
		t.Fatalf("failed update changed members: %v %v", members, err)
	}
	if err := s.RevokeDevice(ctx, "b"); err != nil {
		t.Fatal(err)
	}
	if members, _ := s.GroupDevices(ctx, id); !slices.Equal(members, []string{"a"}) {
		t.Fatalf("revoked device still targeted: %v", members)
	}
	groups, err := s.ListGroups(ctx)
	if err != nil || len(groups) != 1 || len(groups[0].Devices) != 2 {
		t.Fatalf("list: %+v %v", groups, err)
	}
	if err := s.DeleteGroup(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteGroup(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := s.SetGroupDevices(ctx, id, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown group: %v", err)
	}
}
