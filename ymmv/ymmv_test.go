package main

import "testing"

func TestPadRight(t *testing.T) {
	cases := []struct {
		s string
		length int
		pad string
		want string
	}{
		// empty case
		{"", 0, "", ""},
		// string already long enough
		{"y", 1, "x", "y"},
		// string longer than desired
		{"hello", 1, "x", "hello"},
		// normal padding
		{"fire", 5, "s", "fires"},
		{"fire", 8, "s", "firessss"},
		// pad with string of multiple characters
		{"", 9, "abc", "abcabcabc"},
		{"", 10, "abc", "abcabcabca"},
	}
	for _, c := range cases {
		got := PadRight(c.s, c.length, c.pad)
		if got != c.want {
			t.Errorf("PadRight(%q, %d, %q) == %q, want %q",
			         c.s, c.length, c.pad, got, c.want)
		}
	}
}

