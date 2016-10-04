package main

import (
	"testing"
    "time"
)

func TestUseTTL(t *testing.T) {
	cases := []struct {
		ttl    uint32
		want   time.Duration
	}{
		{ 0, time.Second * time.Duration(0+1) },
		{ 1, time.Second * time.Duration(1+1) },
		{ 2, time.Second * time.Duration(2+1) },
		{ 3600, time.Second * time.Duration(3600+1) },
		{ 86400, time.Second * time.Duration(86400+1) },
		{ 86401, time.Second * time.Duration(86400+1) },
		{ 9999999, time.Second * time.Duration(86400+1) },
	}
	for _, c := range cases {
		got := use_ttl(c.ttl)
		if got != c.want {
			t.Errorf("use_ttl(%q) == %q, want %q", c.ttl, got, c.want)
		}
	}
}
