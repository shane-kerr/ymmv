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

func pad_right(s string, length int, pad string) string {
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
	fmt.Printf("%s\n", pad_right(header, 78, "="))
	fmt.Printf("%s\n", y.query)
	if y.query_time.Unix() == 0 {
		fmt.Printf(";; WHEN: unknown\n")
	} else {
		fmt.Printf(";; WHEN: %s\n", y.query_time)
	}
	fmt.Printf("%s\n", pad_right("", 78, "-"))
	fmt.Printf("%s\n", y.answer)
	if y.answer_time.Unix() == 0 {
		fmt.Printf(";; WHEN: unknown\n")
	} else {
		fmt.Printf(";; WHEN: %s\n", y.answer_time)
	}
	fmt.Printf("%s\n", pad_right("", 78, "-"))
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

func lookup_yeti_servers() []net.IP {
	// get the list of root servers from a known Yeti root server
	root_client := new(dns.Client)
	root_client.Net = "tcp"
	ns_query := new(dns.Msg)
	ns_query.SetQuestion(".", dns.TypeNS)
	ns_query.RecursionDesired = true
	// TODO: avoid hard-coding a particular root server here
	ns_response, _, err := dnsstub.DnsQuery("yeti-ns.wide.ad.jp.:53", ns_query)
	if err != nil {
		log.Fatalf("Error looking up Yeti root server NS; %s", err)
	}

	// lookup the addresses of some of our Yeti servers
	resolver, err := dnsstub.Init(16, nil)
	if err != nil {
		log.Fatalf("Error setting up DNS stub resolver: %s\n", err)
	}
	for _, root_server := range ns_response.Answer {
		switch root_server.(type) {
		case *dns.NS:
			ns := root_server.(*dns.NS).Ns
			resolver.Query(ns, dns.TypeAAAA)
		}
	}
	ips := make([]net.IP, 0, 1)
	for n := range ns_response.Answer {
		fmt.Printf("\rLooking up Yeti root servers [%d/%d]",
			n, len(ns_response.Answer))
		answer, _, qname, _, err := resolver.Wait()
		if err != nil {
			fmt.Printf("\nError looking up %s: %s\n", qname, err)
		}
		if answer != nil {
			for _, root_address := range answer.Answer {
				switch root_address.(type) {
				case *dns.AAAA:
					aaaa := root_address.(*dns.AAAA).AAAA
					ips = append(ips, aaaa)
				}
			}
		}
	}
	fmt.Printf("\rLooking up Yeti root servers [%d/%d]\n",
		len(ns_response.Answer), len(ns_response.Answer))
	resolver.Close()

	return ips
}

type yeti_server_set struct {
	algorithm     string
	ips           []net.IP
	rtt_durations []time.Duration
	rtt_times     []time.Time
	next_server   int
}

func init_yeti_server_set(algorithm string, ips []net.IP) (srvs *yeti_server_set) {
	// TODO: check algorithm is "round-robin", "random", "all", or "rtt"
	srvs = new(yeti_server_set)
	srvs.algorithm = algorithm
	if len(ips) == 0 {
		srvs.ips = lookup_yeti_servers()
	} else {
		srvs.ips = ips
	}
	// TODO: sort ips
	srvs.rtt_durations = make([]time.Duration, len(srvs.ips), len(srvs.ips))
	srvs.rtt_times = make([]time.Time, len(srvs.ips), len(srvs.ips))
	srvs.next_server = 0
	return srvs
}

func (srvs *yeti_server_set) next() (ips []net.IP) {
	ips = make([]net.IP, 0, 0)
	if srvs.algorithm == "round-robin" {
		ips = append(ips, srvs.ips[srvs.next_server])
		srvs.next_server = (srvs.next_server + 1) % len(srvs.ips)
	} else if srvs.algorithm == "all" {
		ips = srvs.ips
	} else if srvs.algorithm == "random" {
		// XXX: should seed the random number generator
		ips = append(ips, srvs.ips[rand.Intn(len(srvs.ips))])
	}
	return ips
}

type yeti_server_generator struct {
	servers *yeti_server_set
	ips     chan []net.IP
}

func init_yeti_server_generator(algorithm string, ips []net.IP) (gen *yeti_server_generator) {
	gen = new(yeti_server_generator)
	gen.servers = init_yeti_server_set(algorithm, ips)
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
		key := fmt.Sprintf("%06d_", rr.Header().Rrtype) + strings.ToLower(rr.Header().Name)
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

func compare_section(iana []dns.RR, yeti []dns.RR) (iana_only []dns.RR, yeti_only []dns.RR) {
	// We use nested loops, which not especially efficient,
	// but we only expect a small number of RR in a section
	iana_only = make([]dns.RR, 0)
	yeti_only = make([]dns.RR, len(yeti))
	copy(yeti_only, yeti)
	for _, iana_rr := range iana {
		found := false
		// don't compare signatures
		if iana_rr.Header().Rrtype == dns.TypeRRSIG {
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
	return iana_only, yeti_only
}

func skip_comparison(query *dns.Msg) bool {
	if query.Question[0].Name == "id.server." {
		return true
	}
	if query.Question[0].Name == "hostname.bind." {
		return true
	}
	return false
}

func compare_resp(iana *dns.Msg, yeti *dns.Msg) (result string) {
	// shortcut comparison for some queries
	if skip_comparison(iana) {
		return ""
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
	if iana.CheckingDisabled != yeti.CheckingDisabled {
		result += fmt.Sprintf("Checking disabled flag mismatch: IANA %t vs Yeti %t\n",
			iana.CheckingDisabled, yeti.CheckingDisabled)
		equivalent = false
	}
	if iana.Rcode != yeti.Rcode {
		result += fmt.Sprintf("Rcode mismatch: IANA %s vs Yeti %s\n",
			dns.RcodeToString[iana.Rcode],
			dns.RcodeToString[yeti.Rcode])
		equivalent = false
	}
	is_root_soa_query := false
	if (len(iana.Question) != 1) || (len(yeti.Question) != 1) {
		result += fmt.Sprintf("Bogus number of questions: IANA %d, Yeti %d\n",
			len(iana.Question), len(yeti.Question))
		equivalent = false
	} else {
		if iana.Question[0] != yeti.Question[0] {
			result += fmt.Sprintf("Question mismatch: IANA %s vs Yeti %s\n",
				iana.Question[0], yeti.Question[0])
			equivalent = false
		}
		if (iana.Question[0].Qtype == dns.TypeSOA) &&
                   (iana.Question[0].Name == ".") {
			is_root_soa_query = true
		}
	}
	if is_root_soa_query {
		if len(iana.Answer) != 1 {
			equivalent = false
			result += "IANA missing SOA for .\n"
		}
		if len(yeti.Answer) != 1 {
			equivalent = false
			result += "Yeti missing SOA for .\n"
		}
		if equivalent {
			iana_soa := iana.Answer[0].(*dns.SOA)
			yeti_soa := yeti.Answer[0].(*dns.SOA)
/*
			if iana_soa.Ns != yeti_soa.Ns {
				equivalent = false
				result += fmt.Sprintf("IANA SOA primary master: %s, Yeti SOA primary master: %s\n",
					iana_soa.Ns, yeti_soa.Ns)
			}
			if iana_soa.Mbox != yeti_soa.Mbox {
				equivalent = false
				result += fmt.Sprintf("IANA SOA email: %s, Yeti SOA email: %s\n",
					iana_soa.Mbox, yeti_soa.Mbox)
			}
 */
			if iana_soa.Serial != yeti_soa.Serial {
				equivalent = false
				result += fmt.Sprintf("IANA SOA serial: %d, Yeti SOA serial: %d\n",
					iana_soa.Serial, yeti_soa.Serial)
			}
			if iana_soa.Refresh != yeti_soa.Refresh {
				equivalent = false
				result += fmt.Sprintf("IANA SOA refresh: %d, Yeti SOA refresh: %d\n",
					iana_soa.Refresh, yeti_soa.Refresh)
			}
			if iana_soa.Retry != yeti_soa.Retry {
				equivalent = false
				result += fmt.Sprintf("IANA SOA retry: %d, Yeti SOA retry: %d\n",
					iana_soa.Retry, yeti_soa.Retry)
			}
			if iana_soa.Expire != yeti_soa.Expire {
				equivalent = false
				result += fmt.Sprintf("IANA SOA expiry: %d, Yeti SOA expiry: %d\n",
					iana_soa.Expire, yeti_soa.Expire)
			}
			if iana_soa.Minttl != yeti_soa.Minttl {
				equivalent = false
				result += fmt.Sprintf("IANA SOA negative TTL: %d, Yeti SOA negative TTL: %d\n",
					iana_soa.Minttl, yeti_soa.Minttl)
			}
		}
	} else {
		sort.Sort(rr_sort(iana.Answer))
		sort.Sort(rr_sort(yeti.Answer))
		iana_only, yeti_only := compare_section(iana.Answer, yeti.Answer)
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
		sort.Sort(rr_sort(iana.Ns))
		sort.Sort(rr_sort(yeti.Ns))
		iana_only, yeti_only = compare_section(iana.Ns, yeti.Ns)
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
	}
	sort.Sort(rr_sort(iana.Extra))
	sort.Sort(rr_sort(yeti.Extra))
	iana_only, yeti_only := compare_additional(iana.Extra, yeti.Extra)
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
		result += fmt.Sprintf("Sending query '%s' %s to %s\n",
			iana_query.Question[0].Name,
			dns.TypeToString[iana_query.Question[0].Qtype],
			server)
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
func main() {
	// parse any target IP specified on startup
	ips := make([]net.IP, 0, 0)
	if len(os.Args) > 1 {
		for _, server := range os.Args[1:] {
			ip := net.ParseIP(server)
			// TODO: allow host name here
			if ip == nil {
				log.Fatalf("Unrecognized IP address '%s'\n",
					server)
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

		// TODO: look up Yeti root servers periodically (re-priming)
	}

	// wait for any outstanding queries to finish before exiting
	for query_count > 0 {
		fmt.Print(<-query_output)
		query_count -= 1
	}
}
