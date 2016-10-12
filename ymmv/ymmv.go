package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/golang/glog"
	"github.com/miekg/dns"
	"github.com/shane-kerr/ymmv/dnsstub"
	"gopkg.in/gomail.v2"
	"io"
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
	header := fmt.Sprintf("===[ ymmv message (IPv%d, %s, %s) ]", y.ip_family, protocol_str, y.addr)
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
		errmsg := fmt.Sprintf("Expecting '4' or '6' for IP family, got '%s'", tmp_ip_family)
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
		errmsg := fmt.Sprintf("Expecting 't'cp or 'u'dp for protocol, got '%s'", protocol)
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
		errmsg := fmt.Sprintf("Only read %d of %d bytes of address", nread, cap(tmp_addr))
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
	// skip queries for server information
	if name == "id.server." {
		return true
	}
	if name == "version.server." {
		return true
	}
	if name == "version.bind." {
		return true
	}
	if name == "hostname.bind." {
		return true
	}
	// the IANA servers are authoritative for ROOT-SERVERS.NET, we are not
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

func compare_soa(iana_soa *dns.SOA, yeti_soa *dns.SOA) (diffs []string) {
	if iana_soa == nil {
		if yeti_soa != nil {
			diffs = append(diffs, fmt.Sprintf("SOA only for Yeti: %s", yeti_soa))
		}
		return diffs
	}
	if yeti_soa == nil {
		diffs = append(diffs, fmt.Sprintf("SOA only for IANA: %s", iana_soa))
		return diffs
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
		diffs = append(diffs,
			fmt.Sprintf("IANA SOA serial: %d, Yeti SOA serial: %d", iana_soa.Serial, yeti_soa.Serial))
	}
	if iana_soa.Refresh != yeti_soa.Refresh {
		diffs = append(diffs,
			fmt.Sprintf("IANA SOA refresh: %d, Yeti SOA refresh: %d", iana_soa.Refresh, yeti_soa.Refresh))
	}
	if iana_soa.Retry != yeti_soa.Retry {
		diffs = append(diffs,
			fmt.Sprintf("IANA SOA retry: %d, Yeti SOA retry: %d", iana_soa.Retry, yeti_soa.Retry))
	}
	if iana_soa.Expire != yeti_soa.Expire {
		diffs = append(diffs,
			fmt.Sprintf("IANA SOA expiry: %d, Yeti SOA expiry: %d", iana_soa.Expire, yeti_soa.Expire))
	}
	if iana_soa.Minttl != yeti_soa.Minttl {
		diffs = append(diffs,
			fmt.Sprintf("IANA SOA negative TTL: %d, Yeti SOA negative TTL: %d", iana_soa.Minttl, yeti_soa.Minttl))
	}

	return diffs
}

func compare_resp(iana *dns.Msg, yeti *dns.Msg) (diffs []string) {
	if iana.Response != yeti.Response {
		diffs = append(diffs,
			fmt.Sprintf("Response flag mismatch: IANA %s vs Yeti %s", iana.Response, yeti.Response))
	}
	if iana.Opcode != yeti.Opcode {
		diffs = append(diffs,
			fmt.Sprintf("Opcode mismatch: IANA %s vs Yeti %s",
				dns.OpcodeToString[iana.Opcode], dns.OpcodeToString[yeti.Opcode]))
	}
	if iana.Authoritative != yeti.Authoritative {
		diffs = append(diffs,
			fmt.Sprintf("Authoritative flag mismatch: IANA %t vs Yeti %t",
				iana.Authoritative, yeti.Authoritative))
	}
	// truncated... hmmm...
	if iana.RecursionDesired != yeti.RecursionDesired {
		diffs = append(diffs,
			fmt.Sprintf("Recursion desired flag mismatch: IANA %t vs Yeti %t",
				iana.RecursionDesired, yeti.RecursionDesired))
	}
	if iana.RecursionAvailable != yeti.RecursionAvailable {
		diffs = append(diffs,
			fmt.Sprintf("Recursion available flag mismatch: IANA %t vs Yeti %t",
				strconv.FormatBool(iana.RecursionAvailable), strconv.FormatBool(yeti.RecursionAvailable)))
	}
	if iana.AuthenticatedData != yeti.AuthenticatedData {
		diffs = append(diffs,
			fmt.Sprintf("Authenticated data flag mismatch: IANA %t vs Yeti %t",
				iana.AuthenticatedData, yeti.AuthenticatedData))
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
		diffs = append(diffs,
			fmt.Sprintf("Rcode mismatch: IANA %s vs Yeti %s",
				dns.RcodeToString[iana.Rcode], dns.RcodeToString[yeti.Rcode]))
	}
	sort.Sort(rr_sort(iana.Answer))
	sort.Sort(rr_sort(yeti.Answer))
	iana_only, yeti_only, iana_root_soa, yeti_root_soa := compare_section(iana.Answer, yeti.Answer)
	if (len(iana_only) > 0) || (len(yeti_only) > 0) {
		if len(iana_only) > 0 {
			for _, rr := range iana_only {
				diffs = append(diffs, fmt.Sprintf("Answer section, IANA only: %s", rr))
			}
		}
		if len(yeti_only) > 0 {
			for _, rr := range yeti_only {
				diffs = append(diffs, fmt.Sprintf("Answer section, Yeti only: %s", rr))
			}
		}
	}
	diffs = append(diffs, compare_soa(iana_root_soa, yeti_root_soa)...)
	sort.Sort(rr_sort(iana.Ns))
	sort.Sort(rr_sort(yeti.Ns))
	iana_only, yeti_only, iana_root_soa, yeti_root_soa = compare_section(iana.Ns, yeti.Ns)
	if (len(iana_only) > 0) || (len(yeti_only) > 0) {
		if len(iana_only) > 0 {
			for _, rr := range iana_only {
				diffs = append(diffs, fmt.Sprintf("Authority section, IANA only: %s", rr))
			}
		}
		if len(yeti_only) > 0 {
			for _, rr := range yeti_only {
				diffs = append(diffs, fmt.Sprintf("Authority section, Yeti only: %s", rr))
			}
		}
	}
	diffs = append(diffs, compare_soa(iana_root_soa, yeti_root_soa)...)
	sort.Sort(rr_sort(iana.Extra))
	sort.Sort(rr_sort(yeti.Extra))
	iana_only, yeti_only = compare_additional(iana.Extra, yeti.Extra)
	if (len(iana_only) > 0) || (len(yeti_only) > 0) {
		if len(iana_only) > 0 {
			for _, rr := range iana_only {
				diffs = append(diffs, fmt.Sprintf("Additional section, IANA mismatch: %s", rr))
			}
		}
		if len(yeti_only) > 0 {
			for _, rr := range yeti_only {
				diffs = append(diffs, fmt.Sprintf("Additional section, Yeti mismatch: %s", rr))
			}
		}
	}

	return diffs
}

/*
   We want to provide the option of obfuscating the queries that we
   are comparing, so that we don't expose the actual end-user
   queries. However, we still want to get the same answer to the
   query as the IANA root servers returned.

   In order to do this, we take a hash of any labels that appear to
   the left of the TLD and make a string like:

       ymmv.845a838696ae1e5a.example.

   We combine the labels with a value that only we know, so that an
   observer cannot know what the original query was. (This value may
   be set at startup, otherwise a random value is used.)
*/

var obfuscate_secret []byte

func obfuscate_query(qname_in string) (qname_out string) {
	// split into labels
	labels := strings.FieldsFunc(qname_in, func(r rune) bool { return r == '.' })

	// if we only have a TLD or root, then we need to leave the query alone
	if len(labels) < 2 {
		return strings.ToLower(strings.Join(labels, ".")) + "."
	}

	// check to see if we have an obfuscation secret, and populate if not
	if obfuscate_secret == nil {
		obfuscate_secret = make([]byte, 8, 8)
		nread, err := rand.Read(obfuscate_secret)
		if err != nil {
			glog.Fatalf("Error generating random obfuscation secret: %s", err)
		}
		if nread != 8 {
			glog.Fatalf("Read %d bytes for random obfuscation secret, wanted 8", nread)
		}
		hex_output := make([]byte, 16, 16)
		hex.Encode(hex_output, obfuscate_secret)
		glog.Infof("generated random obfuscation secret %s", strings.ToUpper(string(hex_output)))
	}
	hash_input := append(obfuscate_secret, []byte(strings.ToLower(strings.Join(labels, ".")))...)
	hashed := sha256.Sum256(hash_input)
	hashed_hex := make([]byte, 64, 64)
	hex.Encode(hashed_hex, hashed[:])
	qname_out = "ymmv." + string(hashed_hex[0:16]) + "."
	qname_out += strings.ToLower(strings.Join(labels[len(labels)-1:len(labels)], ".")) + "."

	glog.V(2).Infof("obfuscated %s to %s", qname_in, qname_out)
	return qname_out
}

// If the DNS message already has an OPT record, change the values for UDP buffer size.
// If the DNS message does not already have an OPT record, add one (with DO=0).
func SetOrChangeUDPSize(msg *dns.Msg, udpsize uint16) *dns.Msg {
	e := msg.IsEdns0()
	if e == nil {
		msg.SetEdns0(udpsize, false)
	} else {
		e.SetUDPSize(udpsize)
	}
	return msg
}

func yeti_query(sync chan bool, report *report_conf, srvs *yeti_server_set,
	clear_names bool, edns_size uint16, pf *daily_file, df *daily_file,
	iana_query *dns.Msg, iana_resp *dns.Msg, iana_query_time time.Duration,
	iana_ip *net.IP) {
	org_qname := iana_query.Question[0].Name
	qtype := dns.TypeToString[iana_query.Question[0].Qtype]

	// early exit if we are skipping this query
	if skip_comparison(iana_query) {
		glog.V(1).Infof("skipping query for %s %s", org_qname, qtype)
		sync <- true
		return
	}

	var qname string
	if clear_names {
		qname = iana_query.Question[0].Name
	} else {
		qname = obfuscate_query(iana_query.Question[0].Name)
	}
	for _, target := range srvs.next() {
		glog.V(2).Infof("using server selection %s @ %s", target.ns_name, target.ip)
		server := "[" + target.ip.String() + "]:53"
		glog.V(1).Infof("sending query '%s' %s as '%s' to %s @ %s\n",
			org_qname, qtype, qname, target.ns_name, server)
		// convert to our obfuscated name
		iana_query.Question[0].Name = qname
		// set our EDNS buffer size to a magic number
		if edns_size != 0 {
			SetOrChangeUDPSize(iana_query, edns_size)
		}
		// do the actual query
		yeti_resp, rtt, err := dnsstub.DnsQuery(server, iana_query)
		if err != nil {
			glog.Infof("Error querying Yeti root server %s @ %s; %s\n", target.ns_name, server, err)
			// give a big penalty to our smoothed round-trip time (SRTT)
			srvs.update_srtt(target.ip, time.Second/2)
		} else {
			var rolled bool = false
			diffs := compare_resp(iana_resp, yeti_resp)
			if len(diffs) > 0 {
				glog.Infof("Differences in response for %s %s from %s @ %s\n",
					org_qname, qtype, target.ns_name, server)
				if df.write_diffs(org_qname, qtype, iana_ip, &target.ip, diffs) {
					rolled = true
				}
			}
			// record our performance difference, if desired
			if pf != nil {
				if pf.write_perf(org_qname, qtype, iana_query_time, rtt, iana_ip, &target.ip) {
					rolled = true
				}
			}
			// update our smoothed round-trip time (SRTT)
			srvs.update_srtt(target.ip, rtt)
			// report the results
			if rolled {
				report.send_report(df.old_name, pf.old_name)
			}
		}
		glog.Flush()
	}

	sync <- true
}

func message_reader(output chan *ymmv_message) {
	for {
		y, err := read_next_message()
		if (err != nil) && (err != io.EOF) {
			glog.Fatal(err)
		}
		output <- y
		if y == nil {
			break
		}
	}
}

// define our supported ways of reporting via e-mail
type report_type uint

const (
	mail_sendmail report_type = iota // invoke MTA locally
	mail_smtp                 = iota // deliver mail via SMTP
)

// how we report results (only via e-mail now)
type report_conf struct {
	report_type report_type
	// to set sendmail location
	mail_prog string
	// to set the server to connect to
	mail_server string
	mail_port   int
	// the authentication details if we need it
	mail_user string
	mail_pass string
	// the e-mail source & destination
	mail_from string
	mail_to   string
}

func (cfg *report_conf) send_report(diff_fname string, perf_fname string) {
	// if we have nothing to report, we are done
	if (diff_fname == "") && (perf_fname == "") {
		glog.V(1).Infof("skipping report since there are no log files")
		return
	}

	// build our message
	m := gomail.NewMessage()
	m.SetHeader("From", cfg.mail_from)
	if cfg.mail_to != "" {
		m.SetHeader("To", cfg.mail_to)
	}
	hostname, err := os.Hostname()
	if err != nil {
		glog.Warning("error getting hostname: %s", err)
		hostname = "*unknown*"
	}
	subject := fmt.Sprintf("ymmv report : %s : %s : %s", hostname, diff_fname, perf_fname)
	m.SetHeader("Subject", subject)
	m.SetBody("text/plain", "ymmv report, details in attached log files")
	if diff_fname != "" {
		m.Attach(diff_fname)
	}
	if perf_fname != "" {
		m.Attach(perf_fname)
	}

	// send the message
	if cfg.report_type == mail_smtp {
		glog.V(1).Infof("sending SMTP report to %s via %s %s:%d",
			cfg.mail_to, cfg.mail_user, cfg.mail_server, cfg.mail_port)
		//		d := gomail.Dialer{Host: cfg.mail_server, Port: cfg.mail_port,
		//			Username: cfg.mail_user, Password: cfg.mail_pass}
		d := gomail.Dialer{Host: cfg.mail_server, Port: cfg.mail_port}
		if cfg.mail_user != "" {
			d.Username = cfg.mail_user
		}
		if cfg.mail_pass != "" {
			d.Password = cfg.mail_pass
		}
		err := d.DialAndSend(m)
		if err != nil {
			glog.Errorf("error sending report: %s", err)
		} else {
			user_str := cfg.mail_user
			if user_str != "" {
				user_str = user_str + "@"
			}
			glog.Infof("sent SMTP report to %s via %s%s:%d",
				cfg.mail_to, user_str, cfg.mail_server, cfg.mail_port)
		}
	}
}

type daily_file struct {
	name     string       // base file name
	header   string       // header to put at the top of each file
	last_day uint         // day we wrote to the file last, year*10000 + month*100 + day
	old_name string       // previous name of the file
	cur_name string       // current name of the file
	writer   *os.File     // current file we are writing to
	report   *report_conf // configuration of the reporting, if any
	lock     sync.Mutex
}

// roll to a new file if necessary
// lock must be held before calling
func (df *daily_file) roll_daily_file() (bool, error) {
	y, m, d := time.Now().UTC().Date()
	this_day := uint((y * 10000) + (int(m) * 100) + d)

	// if we are on a different day then when we wrote the last time
	if this_day != df.last_day {
		df.last_day = this_day

		// close any previously open files
		if df.writer != nil {
			err := df.writer.Close()
			if err != nil {
				return false, err
			}
		}

		// open the new file
		fname := fmt.Sprintf("%s.%4d-%2d-%2d.log", df.name, y, m, d)
		var err error
		df.writer, err = os.OpenFile(fname, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return false, err
		}
		df.old_name = df.cur_name
		df.cur_name = fname
		// write a header if the file is empty
		if df.header != "" {
			fi, err := df.writer.Stat()
			if err != nil {
				return false, err
			}
			if fi.Size() == 0 {
				fmt.Fprintln(df.writer, df.header)
			}
		}
		return true, nil
	} else {
		return false, nil
	}
}

func open_daily_file(name string, header string) (*daily_file, error) {
	df := new(daily_file)
	df.name = name
	df.header = header
	_, err := df.roll_daily_file()
	if err != nil {
		return nil, err
	}
	return df, nil
}

func (pf *daily_file) write_perf(qname string, qtype string,
	iana_time time.Duration, yeti_time time.Duration, iana_ip *net.IP, yeti_ip *net.IP) bool {

	pf.lock.Lock()
	defer pf.lock.Unlock()

	rolled, err := pf.roll_daily_file()
	if err != nil {
		glog.Fatalf("Error rolling performance file %s", err)
	}

	fmt.Fprintf(pf.writer, "%s, %6.6f, %6.6f, %20s, %35s, %11s, %s\n",
		time.Now().UTC().Format("2006-01-02T15:04:05"),
		iana_time.Seconds(), yeti_time.Seconds(), iana_ip, yeti_ip, qtype, qname)
	pf.writer.Sync()

	return rolled
}

func (df *daily_file) write_diffs(qname string, qtype string,
	iana_ip *net.IP, yeti_ip *net.IP, diffs []string) bool {

	df.lock.Lock()
	defer df.lock.Unlock()

	rolled, err := df.roll_daily_file()
	if err != nil {
		glog.Fatalf("Error rolling differences file %s", err)
	}

	fmt.Fprintln(df.writer,
		"================================================================================")
	fmt.Fprintf(df.writer, "%s\n", time.Now().UTC().Format("2006-01-02T15:04:05"))
	fmt.Fprintf(df.writer, "qname: %s\n", qname)
	fmt.Fprintf(df.writer, "qtype: %s\n", qtype)
	fmt.Fprintf(df.writer, "IANA IP: %s\n", iana_ip)
	fmt.Fprintf(df.writer, "Yeti IP: %s\n", yeti_ip)
	fmt.Fprintln(df.writer, "----------------------------------------")
	for _, diff := range diffs {
		fmt.Fprintf(df.writer, "%s\n", diff)
	}
	df.writer.Sync()

	return rolled
}

// Main function.
func main() {
	clear_names := flag.Bool("c", false, "use non-obfuscated (clear) query names")
	secret := flag.String("s", "",
		"secret for obfuscated query names, hex-encoded (default random-generated)")
	edns_size := flag.Uint("e", 4093,
		"set EDNS0 buffer size (set to 0 to use original query size)")
	select_alg := flag.String("a", "rtt",
		"set server-selection algorithm, either rtt, round-robin, random, or all")
	perf_file_name := flag.String("p", "",
		"base file name to store performance comparison in (default none)")
	diff_file_name := flag.String("d", "",
		"base file name to store difference details in (default none)")

	// mail parameters
	mail_server := flag.String("mail-server", "mxbiz1.qq.com", "SMTP server name")
	mail_port := flag.Uint("mail-port", 25, "SMTP server port")
	mail_user := flag.String("mail-user", "", "SMTP user name (default none)")
	mail_pass := flag.String("mail-pass", "", "SMTP password (default none)")
	//    mail_to := flag.String("mail-to", "ymmv-reports@biigroup.cn", "report e-mail address")
	mail_to := flag.String("mail-to", "shane@biigroup.cn", "report e-mail address")

	// the e-mail source & destination
	flag.Parse()
	var ips []net.IP
	args := flag.Args()
	for _, server := range args {
		ip := net.ParseIP(server)
		// TODO: allow host name here
		if ip == nil {
			fmt.Printf("Unrecognized IP address '%s'\n", server)
			os.Exit(1)
		}
		ips = append(ips, ip)
	}
	glog.V(2).Infof("ips=%s", ips)

	if *secret != "" {
		var err error
		obfuscate_secret, err = hex.DecodeString(*secret)
		if err != nil {
			fmt.Printf("Error decoding secret for obfuscated query names: %s", err)
			os.Exit(1)
		}
		glog.Infof("using obfuscation secret %s", strings.ToUpper(*secret))
	}

	// verify our EDNS buffer size
	if *edns_size > 65535 {
		fmt.Println("Syntax error: EDNS0 buffer size maximum is 65535")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// verify our server-selection algorithm
	_, ok := server_algorithms[*select_alg]
	if !ok {
		fmt.Printf("Syntax error: server algorithm '%s' is not rtt, round-robin, random, or all\n", *select_alg)
		flag.PrintDefaults()
		os.Exit(1)
	}

	// open our performance file, if specified
	var perf_file *daily_file
	if *perf_file_name != "" {
		var err error
		header := "#              time, iana_rtt, yeti_rtt,            iana_root,                           yeti_root,       qtype, qname"
		perf_file, err = open_daily_file(*perf_file_name, header)
		if err != nil {
			fmt.Printf("Error opening performance file '%s': %s\n", perf_file_name, err)
			os.Exit(1)
		}
	}

	// open our differences file, if specified
	var diff_file *daily_file
	if *diff_file_name != "" {
		var err error
		header := ""
		diff_file, err = open_daily_file(*diff_file_name, header)
		if err != nil {
			fmt.Printf("Error opening differences file '%s': %s\n", diff_file_name, err)
			os.Exit(1)
		}
	}

	// configure reporting
	var report_conf report_conf
	report_conf.report_type = mail_smtp
	report_conf.mail_server = *mail_server
	if *mail_port > 65535 {
		fmt.Println("Syntax error: SMTP port must be <= 65535")
		flag.PrintDefaults()
		os.Exit(1)
	}
	report_conf.mail_port = int(*mail_port)
	report_conf.mail_user = *mail_user
	report_conf.mail_pass = *mail_pass
	report_conf.mail_to = *mail_to
	report_conf.mail_from = "ymmv-reports@biigroup.cn"

	var diff_report string
	if diff_file != nil {
		diff_report = diff_file.cur_name
	}
	var perf_report string
	if perf_file != nil {
		perf_report = perf_file.cur_name
	}

	// start a goroutine to read our input
	messages := make(chan *ymmv_message)
	go message_reader(messages)

	// initialize our server set
	servers := init_yeti_server_set(ips, *select_alg)

	// make a channel for finishing comparisons
	query_sync := make(chan bool)

	// keep track of number of outstanding queries
	query_count := 0

	// main loop, gets answers to compare and collects the results
	for {
		glog.Flush()
		select {
		// new answer to compare
		case y := <-messages:
			if y == nil {
				break
			}
			go yeti_query(query_sync, &report_conf, servers, *clear_names, uint16(*edns_size),
				perf_file, diff_file, y.query, y.answer, y.answer_time.Sub(y.query_time), y.addr)
			query_count += 1
		// comparison done
		case <-query_sync:
			query_count -= 1
		}
	}

	// wait for any outstanding queries to finish before exiting
	for query_count > 0 {
		<-query_sync
		query_count -= 1
		glog.Flush()
	}
}
