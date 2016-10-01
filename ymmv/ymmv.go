package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/shane-kerr/ymmv/dnsstub"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// debug output
type debug_flag bool

var dbg debug_flag = true
var dbg_log *log.Logger = log.New(os.Stderr, "DEBUG ", log.Lmicroseconds|log.LUTC)

func (dbg debug_flag) Printf(format string, args ...interface{}) {
	if dbg {
		dbg_log.Printf(format, args...)
	}
}

// starting point to find Yeti root servers
var yeti_root_hints = []string{
	"bii.dns-lab.net.",
	"yeti-ns.wide.ad.jp.",
	"yeti-ns.tisf.net.",
}

// maximum TTL to use
//const MAX_TTL = 30
//const MAX_TTL = 300
const MAX_TTL = 86400

// convert a TTL into a bounded duration
func use_ttl(ttl uint32) time.Duration {
	if ttl < 1 {
		ttl = 1
	} else if ttl > MAX_TTL {
		ttl = MAX_TTL
	}
	// TODO: use normal distribution
	result := time.Second * time.Duration(ttl+1)
	return result
}

type ymmv_message struct {
	ip_family   byte
	ip_protocol byte
	addr        *net.IP
	query_time  time.Time
	query       *dns.Msg
	answer_time time.Time
	answer      *dns.Msg
}

func PadRight(s string, length int, pad string) string {
	// if a string is longer than the desired length already, just use it
	if len(s) >= length {
		return s
	}
	// add our padding string until we are long enough
	for len(s) < length {
		s += pad
	}
	// truncate on our return, since our padding string may be multiple
	// characters and result in a string longer than we want
	return s[:length]
}

func (y ymmv_message) print() {
	var protocol_str string
	if y.ip_protocol == 'u' {
		protocol_str = "UDP"
	} else {
		protocol_str = "TCP"
	}
	header := fmt.Sprintf("===[ ymmv message (IPv%d, %s, %s) ]",
		y.ip_family, protocol_str, y.addr)
	fmt.Printf("%s\n", PadRight(header, 78, "="))
	fmt.Printf("%s\n", y.query)
	if y.query_time.Unix() == 0 {
		fmt.Printf(";; WHEN: unknown\n")
	} else {
		fmt.Printf(";; WHEN: %s\n", y.query_time)
	}
	fmt.Printf("%s\n", PadRight("", 78, "-"))
	fmt.Printf("%s\n", y.answer)
	if y.answer_time.Unix() == 0 {
		fmt.Printf(";; WHEN: unknown\n")
	} else {
		fmt.Printf(";; WHEN: %s\n", y.answer_time)
	}
	fmt.Printf("%s\n", PadRight("", 78, "-"))
}

// TODO: return more details with err if underlying calls fail
func read_next_message() (y *ymmv_message, err error) {
	magic := make([]byte, 4, 4)
	nread, err := os.Stdin.Read(magic)
	if err != nil {
		return nil, err
	}
	if nread != 4 {
		errmsg := fmt.Sprintf("Only read %d of 4 magic bytes", nread)
		return nil, errors.New(errmsg)
	}
	if string(magic) != "ymmv" {
		errmsg := fmt.Sprintf("Magic '%s' instead of 'ymmv'", magic)
		return nil, errors.New(errmsg)
	}

	tmp_ip_family := make([]byte, 1, 1)
	nread, err = os.Stdin.Read(tmp_ip_family)
	if err != nil {
		return nil, err
	}
	if nread != 1 {
		return nil, errors.New("Couldn't read IPv4 or IPv6")
	}
	var ip_family int
	if tmp_ip_family[0] == '4' {
		ip_family = 4
	} else if tmp_ip_family[0] == '6' {
		ip_family = 6
	} else {
		errmsg := fmt.Sprintf("Expecting '4' or '6' for IP family, got '%s'",
			tmp_ip_family)
		return nil, errors.New(errmsg)
	}

	protocol := make([]byte, 1, 1)
	nread, err = os.Stdin.Read(protocol)
	if err != nil {
		return nil, err
	}
	if nread != 1 {
		return nil, errors.New("Couldn't read TCP or UDP")
	}
	if (protocol[0] != 'u') && (protocol[0] != 't') {
		errmsg := fmt.Sprintf("Expecting 't'cp or 'u'dp for protocol, got '%s'",
			protocol)
		return nil, errors.New(errmsg)
	}

	var tmp_addr []byte
	if ip_family == 4 {
		tmp_addr = make([]byte, 4, 4)
	} else {
		// XXX: should we add an assert()-equivalent here?
		tmp_addr = make([]byte, 16, 16)
	}
	nread, err = os.Stdin.Read(tmp_addr)
	if err != nil {
		return nil, err
	}
	if nread != cap(tmp_addr) {
		errmsg := fmt.Sprintf("Only read %d of %d bytes of address",
			nread, cap(tmp_addr))
		return nil, errors.New(errmsg)
	}
	addr := net.IP(tmp_addr)

	var query_sec uint32
	err = binary.Read(os.Stdin, binary.BigEndian, &query_sec)
	if err != nil {
		return nil, err
	}
	var query_nsec uint32
	err = binary.Read(os.Stdin, binary.BigEndian, &query_nsec)
	if err != nil {
		return nil, err
	}
	query_time := time.Unix(int64(query_sec), int64(query_nsec))

	var query_len uint16
	err = binary.Read(os.Stdin, binary.BigEndian, &query_len)
	if err != nil {
		return nil, err
	}
	query_raw := make([]byte, query_len, query_len)
	nread, err = os.Stdin.Read(query_raw)
	if err != nil {
		return nil, err
	}
	if nread != int(query_len) {
		errmsg := fmt.Sprintf("Only read %d of %d bytes of query message", nread, query_len)
		return nil, errors.New(errmsg)
	}
	query := new(dns.Msg)
	query.Unpack(query_raw)

	var answer_sec uint32
	err = binary.Read(os.Stdin, binary.BigEndian, &answer_sec)
	if err != nil {
		return nil, err
	}
	var answer_nsec uint32
	err = binary.Read(os.Stdin, binary.BigEndian, &answer_nsec)
	if err != nil {
		return nil, err
	}
	answer_time := time.Unix(int64(answer_sec), int64(answer_nsec))

	var answer_len uint16
	err = binary.Read(os.Stdin, binary.BigEndian, &answer_len)
	if err != nil {
		return nil, err
	}
	answer_raw := make([]byte, answer_len, answer_len)
	nread, err = os.Stdin.Read(answer_raw)
	if err != nil {
		return nil, err
	}
	if nread != int(answer_len) {
		errmsg := fmt.Sprintf("Only read %d of %d bytes of answer message", nread, answer_len)
		return nil, errors.New(errmsg)
	}
	answer := new(dns.Msg)
	answer.Unpack(answer_raw)

	var result ymmv_message
	result.ip_family = byte(ip_family)
	result.ip_protocol = protocol[0]
	result.addr = new(net.IP)
	*result.addr = addr
	result.query_time = query_time
	result.query = query
	result.answer_time = answer_time
	result.answer = answer

	return &result, nil
}

// information about each Yeti name server
type ns_info struct {
	// name of the name server, like "bii.dns-lab.net" (may be "")
	name string

	// IP addresses of the name server
	ip []net.IP

	// round-trip time (RTT) of last lookup, or 0 if none
	last_rtt time.Duration

	// time when last lookup happened, or nil if no lookup has yet occurred
	last_lookup *time.Time

	// timer for seeing if the IP address changed (may be nil)
	timer *time.Timer

	// server set we belong to
	srvs *yeti_server_set
}

type yeti_server_set struct {
	// prevent use of data during modification
	lock sync.Mutex

	// timer for refreshing the root zone NS RRset
	root_ns_timer *time.Timer

	// information about each IP address
	ns []*ns_info

	// algorithm used to pick server
	algorithm string

	// next server to use (for round-robin)
	next_server int
	next_ip     int

	// resolver for lookups
	resolver *dnsstub.StubResolver
}

// does a lookup and gets the root NS RRset
func get_root_ns(hints []string) (ns_names []string, ns_ttl uint32) {
	ns_query := new(dns.Msg)
	ns_query.SetQuestion(".", dns.TypeNS)
	ns_query.RecursionDesired = true

	// Try each of our servers listed in our hints until one works.
	// Use the rand.Perm() function so we try them in a random order.
	var ns_response *dns.Msg
	for _, n := range rand.Perm(len(hints)) {
		root := hints[n]
		if !strings.ContainsRune(root, ':') {
			root = root + ":53"
		}
		var err error
		ns_response, _, err = dnsstub.DnsQuery(root, ns_query)
		if err != nil {
			log.Printf("Error looking up Yeti root server NS from %s; %s", root, err)
		}
		if ns_response != nil {
			break
		}
	}
	if ns_response == nil {
		log.Fatalf("Unable to get NS from any Yeti root server")
	}

	// extract out the names from the NS RRset, and also save the TTL
	for _, root_server := range ns_response.Answer {
		switch root_server.(type) {
		case *dns.NS:
			ns_names = append(ns_names, root_server.(*dns.NS).Ns)
			ns_ttl = root_server.Header().Ttl
		}
	}

	if len(ns_names) == 0 {
		log.Fatalf("No NS found for Yeti root")
	}

	// insure our order is repeatable
	sort.Strings(ns_names)

	return ns_names, ns_ttl
}

func refresh_ns(srvs *yeti_server_set) {
	dbg.Printf("refreshing root NS list")

	ns_names, ns_ttl := get_root_ns(yeti_root_hints)

	srvs.lock.Lock()
	n := 0
	for _, name := range ns_names {
		// remove any names that are no longer present
		for (len(srvs.ns) > n) && (srvs.ns[n].name < name) {
			if !srvs.ns[n].timer.Stop() {
				<-srvs.ns[n].timer.C
			}
			srvs.ns = append(srvs.ns[:n], srvs.ns[n+1:]...)
		}
		// if name is the same, we are good, advance to next name
		if srvs.ns[n].name == name {
			n++
			// otherwise we have to add it
		} else {
			new_ns := &ns_info{name: name, srvs: srvs}
			srvs.ns = append(srvs.ns, nil)
			copy(srvs.ns[n+1:], srvs.ns[n:])
			srvs.ns[n] = new_ns
			go refresh_aaaa(new_ns, nil)
		}
	}
	srvs.lock.Unlock()

	// set timer to refresh our NS RRset
	srvs.root_ns_timer = time.AfterFunc(use_ttl(ns_ttl), func() { refresh_ns(srvs) })
}

// Note that on error we don't use this name server until we can find out
// the IP address for it. In theory we could use the name server until the
// TTL for the address expires, but rather than track that we just
// temporarily stop using it.
func refresh_aaaa(ns *ns_info, done chan int) {
	dbg.Printf("refreshing %s", ns.name)

	var new_ip []net.IP
	var this_ttl uint32

	answer, _, err := ns.srvs.resolver.SyncQuery(ns.name, dns.TypeAAAA)
	if err != nil {
		log.Printf("Error looking up %s: %s\n", ns.name, err)
	}

	if answer != nil {
		for _, root_address := range answer.Answer {
			switch root_address.(type) {
			case *dns.AAAA:
				aaaa := root_address.(*dns.AAAA).AAAA
				dbg.Printf("AAAA for %s = %s", ns.name, aaaa)
				new_ip = append(new_ip, aaaa)
				this_ttl = root_address.Header().Ttl
			}
		}
	}

	if len(new_ip) == 0 {
		log.Printf("No AAAA for %s, checking again in 300 seconds", ns.name)
		this_ttl = 300
	}

	ns.srvs.lock.Lock()
	ns.ip = new_ip
	when := use_ttl(this_ttl)
	dbg.Printf("scheduling refresh of AAAA for %s in %s\n", ns.name, when)
	ns.timer = time.AfterFunc(when, func() { refresh_aaaa(ns, nil) })
	ns.srvs.lock.Unlock()

	done <- len(new_ip)
}

// get the list of root servers from known Yeti root servers
func yeti_priming(srvs *yeti_server_set) {
	// get the names from the NS RRset
	dbg.Printf("getting root NS RRset")
	ns_names, ns_ttl := get_root_ns(yeti_root_hints)

	aaaa_done := make(chan int)
	for _, ns_name := range ns_names {
		this_ns := &ns_info{name: ns_name, srvs: srvs}
		// we want to complete at least one lookup before we return from priming
		go refresh_aaaa(this_ns, aaaa_done)
		srvs.ns = append(srvs.ns, this_ns)
	}

	found_aaaa := false
	for _ = range ns_names {
		num_ip := <-aaaa_done
		if num_ip > 0 {
			found_aaaa = true
			break
		}
	}
	if !found_aaaa {
		log.Fatalf("No AAAA found for Yeti root NS")
	}

	// set timer to refresh our NS RRset
	when := use_ttl(ns_ttl)
	dbg.Printf("scheduling refresh of NS in %s\n", when)
	srvs.root_ns_timer = time.AfterFunc(when, func() { refresh_ns(srvs) })
}

func init_yeti_server_set(ips []net.IP) (srvs *yeti_server_set) {
	srvs = new(yeti_server_set)

	if len(ips) == 0 {
		dbg.Printf("no IP's passed, performing Yeti priming\n")
		var err error
		srvs.resolver, err = dnsstub.Init(4, nil)
		if err != nil {
			log.Fatalf("Error setting up DNS stub resolver: %s\n", err)
		}
		yeti_priming(srvs)
		dbg.Printf("priming done\n")
	} else {
		srvs.ns = append(srvs.ns, &ns_info{ip: ips})
	}

	srvs.algorithm = "round-robin"
	srvs.next_server = 0
	srvs.next_ip = 0

	return srvs
}

// Get the next set of IP addresses to query.
// For most algorithms this is a single address, but it may be more (for "all").
func (srvs *yeti_server_set) next() (ips []net.IP) {
	srvs.lock.Lock()
	defer srvs.lock.Unlock()

	if srvs.algorithm == "round-robin" {
		for srvs.next_ip >= len(srvs.ns[srvs.next_server].ip) {
			srvs.next_server = (srvs.next_server + 1) % len(srvs.ns)
			srvs.next_ip = 0
		}
		ips = append(ips, srvs.ns[srvs.next_server].ip[srvs.next_ip])
		srvs.next_ip = srvs.next_ip + 1
	} else if srvs.algorithm == "rtt" {
		log.Fatalf("rtt-based server selection unimplemented")
	} else {
		var all_ips []net.IP
		for _, ns := range srvs.ns {
			for _, ip := range ns.ip {
				all_ips = append(all_ips, ip)
			}
		}
		if srvs.algorithm == "all" {
			ips = all_ips
		} else if srvs.algorithm == "random" {
			ips = append(ips, all_ips[rand.Intn(len(all_ips))])
		}
	}
	return ips
}

type yeti_server_generator struct {
	servers *yeti_server_set
	ips     chan []net.IP
}

func init_yeti_server_generator(algorithm string, ips []net.IP) (gen *yeti_server_generator) {
	gen = new(yeti_server_generator)
	gen.servers = init_yeti_server_set(ips)
	gen.servers.algorithm = algorithm
	gen.ips = make(chan []net.IP)
	go func() {
		for {
			gen.ips <- gen.servers.next()
		}
	}()
	return gen
}

func (gen *yeti_server_generator) next() (ips []net.IP) {
	return <-gen.ips
}

// RrSort implements functions needed to sort []dns.RR
type rr_sort []dns.RR

func (a rr_sort) Len() int      { return len(a) }
func (a rr_sort) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a rr_sort) Less(i, j int) bool {
	// XXX: is there a "cmp" equivalent in Go?
	// compare name of RR
	i_name := strings.ToLower(a[i].Header().Name)
	j_name := strings.ToLower(a[i].Header().Name)
	if i_name < j_name {
		return true
	} else if i_name > j_name {
		return false
	}

	// compare type of RR
	if a[i].Header().Rrtype < a[j].Header().Rrtype {
		return true
	} else if a[i].Header().Rrtype > a[j].Header().Rrtype {
		return false
	}

	// do not worry about class

	// compare TTL of RR
	if a[i].Header().Ttl < a[j].Header().Ttl {
		return true
	} else if a[i].Header().Ttl > a[j].Header().Ttl {
		return false
	}

	// We want to compare the RDATA, but there does not appear to be
	// a way to easily access that directly, so we will use the string
	// representation.
	case_insensitive := false
	switch a[i].Header().Rrtype {
	case dns.TypeNS:
		case_insensitive = true
	case dns.TypeCNAME:
		case_insensitive = true
	case dns.TypeSOA:
		// possibly not strictly correct, as the mname field might be
		// case-sensitive, but...
		case_insensitive = true
	case dns.TypePTR:
		case_insensitive = true
	case dns.TypeMX:
		case_insensitive = true
	// TODO: double-check the following
	case dns.TypeSRV:
		case_insensitive = true
	case dns.TypeNAPTR:
		case_insensitive = true
	case dns.TypeDNAME:
		case_insensitive = true
	}
	i_str := a[i].String()
	j_str := a[j].String()
	if case_insensitive {
		i_str = strings.ToLower(a[i].String())
		j_str = strings.ToLower(a[j].String())
	}
	if i_str < j_str {
		return true
	}
	return false
}

func extract_rrset(rrs []dns.RR) map[string][]dns.RR {
	rrsets := make(map[string][]dns.RR)
	for _, rr := range rrs {
		rr.Header().Name = strings.ToLower(rr.Header().Name)
		key := fmt.Sprintf("%06d_", rr.Header().Rrtype) + rr.Header().Name
		rrset, ok := rrsets[key]
		if !ok {
			rrset = make([]dns.RR, 0)
		}
		rrset = append(rrset, rr)
		rrsets[key] = rrset
	}
	for _, rrset := range rrsets {
		sort.Sort(rr_sort(rrset))
	}
	return rrsets
}

/*
   Additional section comparison is more difficult than answer or
   authority section comparison.

   What we need to do is pull out all of the RRset in both the IANA
   and Yeti messages. Any RRset that is in *both* messages must be the
   same, otherwise we ignore it.

   Also, we don't really care about the contents of the OPT pseudo-RR,
   as that doesn't contain actual answer data.
*/
func compare_additional(iana []dns.RR, yeti []dns.RR) (iana_only []dns.RR, yeti_only []dns.RR) {
	iana_only = make([]dns.RR, 0)
	yeti_only = make([]dns.RR, 0)
	iana_rr_map := extract_rrset(iana)
	yeti_rr_map := extract_rrset(yeti)
	for key, iana_rrset := range iana_rr_map {
		// don't compare the OPT pseudo-RR
		if iana_rrset[0].Header().Rrtype == dns.TypeOPT {
			continue
		}
		// and don't compare signatures
		if iana_rrset[0].Header().Rrtype == dns.TypeRRSIG {
			continue
		}
		yeti_rrset, ok := yeti_rr_map[key]
		if ok {
			if !reflect.DeepEqual(iana_rrset, yeti_rrset) {
				for _, rr := range iana_rrset {
					iana_only = append(iana_only, rr)
				}
				for _, rr := range yeti_rrset {
					yeti_only = append(yeti_only, rr)
				}
			}
		}
	}
	return iana_only, yeti_only
}

func compare_section(iana []dns.RR, yeti []dns.RR) (iana_only []dns.RR, yeti_only []dns.RR,
	iana_root_soa *dns.SOA, yeti_root_soa *dns.SOA) {
	iana_root_soa = nil
	yeti_root_soa = nil
	iana_only = make([]dns.RR, 0)
	yeti_only = make([]dns.RR, 0, len(yeti))
	for _, yeti_rr := range yeti {
		if (yeti_rr.Header().Rrtype == dns.TypeSOA) && (yeti_rr.Header().Name == ".") {
			yeti_root_soa = yeti_rr.(*dns.SOA)
			continue
		}
		if yeti_rr.Header().Rrtype != dns.TypeRRSIG {
			yeti_only = append(yeti_only, yeti_rr)
		}
	}
	// We use nested loops, which not especially efficient,
	// but we only expect a small number of RR in a section
	for _, iana_rr := range iana {
		found := false
		// don't compare signatures
		if iana_rr.Header().Rrtype == dns.TypeRRSIG {
			continue
		} else if (iana_rr.Header().Rrtype == dns.TypeSOA) && (iana_rr.Header().Name == ".") {
			iana_root_soa = iana_rr.(*dns.SOA)
			continue
		}
		for n, yeti_rr := range yeti_only {
			if strings.ToLower(iana_rr.String()) == strings.ToLower(yeti_rr.String()) {
				yeti_only = append(yeti_only[:n], yeti_only[n+1:]...)
				found = true
				break
			}
		}
		if !found {
			iana_only = append(iana_only, iana_rr)
		}
	}
	return iana_only, yeti_only, iana_root_soa, yeti_root_soa
}

func skip_comparison(query *dns.Msg) bool {
	name := strings.ToLower(query.Question[0].Name)
	// of course the root zone itself is different, so skip that
	if name == "." {
		return true
	}
	if name == "id.server." {
		return true
	}
	if name == "hostname.bind." {
		return true
	}
	if strings.HasSuffix(name, ".root-servers.net.") {
		return true
	}
	// XXX: ARPA is tricky, since some of the IANA root servers
	// are authoritative. For now, just skip these queries.
	if strings.HasSuffix(name, ".arpa.") {
		return true
	}
	return false
}

func compare_soa(iana_soa *dns.SOA, yeti_soa *dns.SOA) (result string) {
	result = ""

	if iana_soa == nil {
		if yeti_soa != nil {
			result += fmt.Sprintf("SOA only for Yeti: %s\n", yeti_soa)
		}
		return result
	}
	if yeti_soa == nil {
		return fmt.Sprintf("SOA only for IANA: %s\n", iana_soa)
	}

	/*
		if iana_soa.Ns != yeti_soa.Ns {
			result += fmt.Sprintf("IANA SOA primary master: %s, Yeti SOA primary master: %s\n",
				iana_soa.Ns, yeti_soa.Ns)
		}
	*/
	/*
		if iana_soa.Mbox != yeti_soa.Mbox {
			result += fmt.Sprintf("IANA SOA email: %s, Yeti SOA email: %s\n",
				iana_soa.Mbox, yeti_soa.Mbox)
		}
	*/
	if iana_soa.Serial != yeti_soa.Serial {
		result += fmt.Sprintf("IANA SOA serial: %d, Yeti SOA serial: %d\n",
			iana_soa.Serial, yeti_soa.Serial)
	}
	if iana_soa.Refresh != yeti_soa.Refresh {
		result += fmt.Sprintf("IANA SOA refresh: %d, Yeti SOA refresh: %d\n",
			iana_soa.Refresh, yeti_soa.Refresh)
	}
	if iana_soa.Retry != yeti_soa.Retry {
		result += fmt.Sprintf("IANA SOA retry: %d, Yeti SOA retry: %d\n",
			iana_soa.Retry, yeti_soa.Retry)
	}
	if iana_soa.Expire != yeti_soa.Expire {
		result += fmt.Sprintf("IANA SOA expiry: %d, Yeti SOA expiry: %d\n",
			iana_soa.Expire, yeti_soa.Expire)
	}
	if iana_soa.Minttl != yeti_soa.Minttl {
		result += fmt.Sprintf("IANA SOA negative TTL: %d, Yeti SOA negative TTL: %d\n",
			iana_soa.Minttl, yeti_soa.Minttl)
	}

	return result
}

func compare_resp(iana *dns.Msg, yeti *dns.Msg) (result string) {
	// shortcut comparison for some queries
	if skip_comparison(iana) {
		return "Skipping query\n"
	}

	result = ""
	equivalent := true
	if iana.Response != yeti.Response {
		result += fmt.Sprintf("Response flag mismatch: IANA %s vs Yeti %s\n",
			iana.Response, yeti.Response)
		equivalent = false
	}
	if iana.Opcode != yeti.Opcode {
		result += fmt.Sprintf("Opcode mismatch: IANA %s vs Yeti %s\n",
			dns.OpcodeToString[iana.Opcode],
			dns.OpcodeToString[yeti.Opcode])
		equivalent = false
	}
	if iana.Authoritative != yeti.Authoritative {
		result += fmt.Sprintf("Authoritative flag mismatch: IANA %t vs Yeti %t\n",
			iana.Authoritative, yeti.Authoritative)
		equivalent = false
	}
	// truncated... hmmm...
	if iana.RecursionDesired != yeti.RecursionDesired {
		result += fmt.Sprintf("Recursion desired flag mismatch: IANA %t vs Yeti %t\n",
			iana.RecursionDesired, yeti.RecursionDesired)
		equivalent = false
	}
	if iana.RecursionAvailable != yeti.RecursionAvailable {
		result += fmt.Sprintf("Recursion available flag mismatch: IANA %t vs Yeti %t\n",
			strconv.FormatBool(iana.RecursionAvailable),
			strconv.FormatBool(yeti.RecursionAvailable))
		equivalent = false
	}
	if iana.AuthenticatedData != yeti.AuthenticatedData {
		result += fmt.Sprintf("Authenticated data flag mismatch: IANA %t vs Yeti %t\n",
			iana.AuthenticatedData, yeti.AuthenticatedData)
		equivalent = false
	}
	// XXX: temporarily disabled
	/*
		if iana.CheckingDisabled != yeti.CheckingDisabled {
			result += fmt.Sprintf("Checking disabled flag mismatch: IANA %t vs Yeti %t\n",
				iana.CheckingDisabled, yeti.CheckingDisabled)
			equivalent = false
		}
	*/
	if iana.Rcode != yeti.Rcode {
		result += fmt.Sprintf("Rcode mismatch: IANA %s vs Yeti %s\n",
			dns.RcodeToString[iana.Rcode],
			dns.RcodeToString[yeti.Rcode])
		equivalent = false
	}
	sort.Sort(rr_sort(iana.Answer))
	sort.Sort(rr_sort(yeti.Answer))
	iana_only, yeti_only, iana_root_soa, yeti_root_soa := compare_section(iana.Answer, yeti.Answer)
	if (len(iana_only) > 0) || (len(yeti_only) > 0) {
		equivalent = false
		if len(iana_only) > 0 {
			result += fmt.Sprint("Answer section, IANA only\n")
			for _, rr := range iana_only {
				result += fmt.Sprintf("%s\n", rr)
			}
		}
		if len(yeti_only) > 0 {
			result += fmt.Sprint("Answer section, Yeti only\n")
			for _, rr := range yeti_only {
				result += fmt.Sprintf("%s\n", rr)
			}
		}
	}
	result += compare_soa(iana_root_soa, yeti_root_soa)
	sort.Sort(rr_sort(iana.Ns))
	sort.Sort(rr_sort(yeti.Ns))
	iana_only, yeti_only, iana_root_soa, yeti_root_soa = compare_section(iana.Ns, yeti.Ns)
	if (len(iana_only) > 0) || (len(yeti_only) > 0) {
		equivalent = false
		if len(iana_only) > 0 {
			result += fmt.Sprint("Authority section, IANA only\n")
			for _, rr := range iana_only {
				result += fmt.Sprintf("%s\n", rr)
			}
		}
		if len(yeti_only) > 0 {
			result += fmt.Sprint("Authority section, Yeti only\n")
			for _, rr := range yeti_only {
				result += fmt.Sprintf("%s\n", rr)
			}
		}
	}
	result += compare_soa(iana_root_soa, yeti_root_soa)
	sort.Sort(rr_sort(iana.Extra))
	sort.Sort(rr_sort(yeti.Extra))
	iana_only, yeti_only = compare_additional(iana.Extra, yeti.Extra)
	if (len(iana_only) > 0) || (len(yeti_only) > 0) {
		equivalent = false
		if len(iana_only) > 0 {
			result += fmt.Sprint("Additional section, IANA mismatch\n")
			for _, rr := range iana_only {
				result += fmt.Sprintf("%s\n", rr)
			}
		}
		if len(yeti_only) > 0 {
			result += fmt.Sprint("Additional section, Yeti mismatch\n")
			for _, rr := range yeti_only {
				result += fmt.Sprintf("%s\n", rr)
			}
		}
	}

	if equivalent {
		//		result += fmt.Print("Equivalent. Yay!\n")
	} else {
		//		result += fmt.Sprintf("---[ IANA ]----\n%s\n---[ Yeti ]----\n%s\n",
		//			iana, yeti)
	}
	return result
}

func yeti_query(gen *yeti_server_generator, iana_query *dns.Msg, iana_resp *dns.Msg, output chan string) {
	result := ""
	for _, ip := range gen.next() {
		server := "[" + ip.String() + "]:53"
		result += log.Prefix()
		result += fmt.Sprintf("Sending query '%s' %s to %s\n",
			iana_query.Question[0].Name,
			dns.TypeToString[iana_query.Question[0].Qtype],
			server)
		// XXX: hack hack set DO bit
		//		iana_query.SetEdns0(4096, true)
		//		yeti_resp, qtime, err := dnsstub.DnsQuery(server, iana_query)
		yeti_resp, _, err := dnsstub.DnsQuery(server, iana_query)
		if err != nil {
			result += fmt.Sprintf("Error querying Yeti root server; %s\n", err)
		} else {
			result += compare_resp(iana_resp, yeti_resp)
		}
	}
	output <- result
}

func message_reader(output chan *ymmv_message) {
	for {
		y, err := read_next_message()
		if (err != nil) && (err != io.EOF) {
			log.Fatal(err)
		}
		output <- y
		if y == nil {
			break
		}
	}
}

// Main function.
// TODO: verbose/debug flags
// XXX: should seed the random number generator
func main() {
	// parse any target IP specified on startup
	var ips []net.IP
	if len(os.Args) > 1 {
		for _, server := range os.Args[1:] {
			ip := net.ParseIP(server)
			// TODO: allow host name here
			if ip == nil {
				log.Fatalf("Unrecognized IP address '%s'\n", server)
			}
			ips = append(ips, ip)
		}
	}

	// start a goroutine to read our input
	messages := make(chan *ymmv_message)
	go message_reader(messages)

	// start a goroutine to generate root server targets
	servers := init_yeti_server_generator("round-robin", ips)

	// make a channel to get our comparison results
	query_output := make(chan string)

	// keep track of number of outstanding queries
	query_count := 0

	// main loop, gets answers to compare and collects the results
	for {
		select {
		// new answer to compare
		case y := <-messages:
			if y == nil {
				break
			}
			go yeti_query(servers, y.query, y.answer, query_output)
			query_count += 1
		// comparison done
		case str := <-query_output:
			fmt.Print(str)
			query_count -= 1
		}
	}

	// wait for any outstanding queries to finish before exiting
	for query_count > 0 {
		fmt.Print(<-query_output)
		query_count -= 1
	}
}
