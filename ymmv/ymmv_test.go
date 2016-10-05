package main

import (
	"encoding/hex"
	"github.com/miekg/dns"
	"strings"
	"testing"
)

func TestPadRight(t *testing.T) {
	cases := []struct {
		s      string
		length int
		pad    string
		want   string
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

func TestObfuscateQuery(t *testing.T) {
	var obf string
	// always start with an empty string...
	obf = obfuscate_query("")
	if obf != "." {
		t.Errorf("TestObfuscateQuery(\"\") == %q, want \".\"", obf)
	}
	// try root
	obf = obfuscate_query(".")
	if obf != "." {
		t.Errorf("TestObfuscateQuery(\".\") == %q, want \".\"", obf)
	}
	// single label
	obf = obfuscate_query("example.")
	if obf != "example." {
		t.Errorf("TestObfuscateQuery(\"example.\") == %q, want \"example.\"", obf)
	}
	// actually anything we pass without a '.' should come back normalized
	obf = obfuscate_query("CheCkIt")
	if obf != "checkit." {
		t.Errorf("TestObfuscateQuery(\"CheCkIt\") == %q, want \"checkit.\"", obf)
	}
	// confirm that a second-level domain gets obfuscated properly
	obf = obfuscate_query("www.example")
	if !strings.HasPrefix(obf, "ymmv.") {
		t.Errorf("TestObfuscateQuery(\"www.example\") == %q, should start with \"ymmv.\"", obf)
	}
	if !strings.HasSuffix(obf, ".example.") {
		t.Errorf("TestObfuscateQuery(\"www.example\") == %q, should end with \".example.\"", obf)
	}
	if len(obf) != (len("ymmv.") + 16 + len(".example.")) {
		t.Errorf("TestObfuscateQuery(\"www.example\") == %q, length is wrong", obf)
	}
	hexbytes := make([]byte, 8)
	num, err := hex.Decode(hexbytes, []byte(obf[len("ymmv."):len(obf)-len(".example.")]))
	if num != 8 {
		t.Errorf("TestObfuscateQuery(\"www.example\") == %q, decoded hext length is %d", obf, num)
	}
	if err != nil {
		t.Errorf("TestObfuscateQuery(\"www.example\") == %q, error with hex.Decode(): ", obf, err)
	}
	// confirm that we get the same string if we change the case
	obf_case := obfuscate_query("WwW.eXaMpLe")
	if obf != obf_case {
		t.Errorf("TestObfuscateQuery(\"WwW.eXaMpLe\") == %q, should be %q", obf_case, obf)
	}
	// confirm that we get a different string for other labels
	obf2 := obfuscate_query("xxx.example")
	if obf == obf2 {
		t.Errorf("TestObfuscateQuery(\"www.example\") == %q, should not be", obf2)
	}
	// confirm that longer sets of labels also differ
	obf3 := obfuscate_query("www.test.example")
	if obf == obf3 {
		t.Errorf("TestObfuscateQuery(\"www.test.example\") == %q, should not be", obf3)
	}
	// confirm that a different TLD gets different results
	obf_tld := obfuscate_query("www.exampel")
	if obf == obf_tld {
		t.Errorf("TestObfuscateQuery(\"www.exampel\") == %q, should not be", obf_tld)
	}
	// verify that the final dot results in the same string
	obf_dot := obfuscate_query("www.example.")
	if obf != obf_dot {
		t.Errorf("TestObfuscateQuery(\"www.example.\") == %q, should be %q", obf_dot, obf)
	}
	// verify that if we change the secret we get different results
	obfuscate_secret = []byte("12345678")
	obf_newsecret := obfuscate_query("www.example")
	if obf == obf_newsecret {
		t.Errorf("TestObfuscateQuery(\"www.example\") == %q, should not be", obf_newsecret)
	}
}

func count_opt(msg *dns.Msg) int {
	count := 0
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			count++
		}
	}
	return count
}

func TestSetOrChangeEdns0(t *testing.T) {
	// make a new message
	msg := new(dns.Msg)
	if count_opt(msg) != 0 {
		t.Errorf("Unexpected OPT record on new message")
	}

	// try our function without any EDNS message
	SetOrChangeEdns0(msg, 1234, false)
	if count_opt(msg) != 1 {
		t.Errorf("%d OPT records, expected 1", count_opt(msg))
	}
	e := msg.IsEdns0()
	if e == nil {
		t.Errorf("Missing OPT record on message")
	}
	if e.Do() != false {
		t.Errorf("DO is 1, should be 0")
	}
	if e.UDPSize() != 1234 {
		t.Errorf("EDNS buffer size is %d, should be 1234", e.UDPSize())
	}

	// try our function with the EDNS message
	SetOrChangeEdns0(msg, 4321, true)
	if count_opt(msg) != 1 {
		t.Errorf("%d OPT records, expected 1", count_opt(msg))
	}
	e = msg.IsEdns0()
	if e == nil {
		t.Errorf("Missing OPT record on message")
	}
	if e.Do() != true {
		t.Errorf("DO is 0, should be 1")
	}
	if e.UDPSize() != 4321 {
		t.Errorf("EDNS buffer size is %d, should be 4321", e.UDPSize())
	}
}
