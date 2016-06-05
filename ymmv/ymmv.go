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
	"strconv"
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
			ip_family)
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

func compare_rrset(iana []dns.RR, yeti []dns.RR) (iana_only []dns.RR, yeti_only []dns.RR) {
	// We use nested loops, which not especially efficient, 
	// but we only expect a small number of RR in an RRset.
	iana_only = make([]dns.RR, 0, 0)
	yeti_only = make([]dns.RR, len(yeti))
	copy(yeti_only, yeti)
	for _, iana_rr := range(iana) {
		found := false
		for n, yeti_rr := range(yeti_only) {
			if iana_rr.String() == yeti_rr.String() {
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

func compare_resp(iana *dns.Msg, yeti *dns.Msg) {
	equivalent := true
	if iana.Response != yeti.Response {
		fmt.Printf("Response flag mismatch: IANA %s vs Yeti %s\n",
			iana.Response, yeti.Response)
		equivalent = false
	}
	if iana.Opcode != yeti.Opcode {
		fmt.Printf("Opcode mismatch: IANA %s vs Yeti %s\n",
			dns.OpcodeToString[iana.Opcode],
			dns.OpcodeToString[yeti.Opcode])
		equivalent = false
	}
	if iana.Authoritative != yeti.Authoritative {
		fmt.Printf("Authoritative flag mismatch: IANA %s vs Yeti %s\n",
			iana.Authoritative, yeti.Authoritative)
		equivalent = false
	}
	// truncated... hmmm...
	if iana.RecursionDesired != yeti.RecursionDesired {
		fmt.Printf("Recursion desired flag mismatch: IANA %s vs Yeti %s\n",
			iana.RecursionDesired, yeti.RecursionDesired)
		equivalent = false
	}
	if iana.RecursionAvailable != yeti.RecursionAvailable {
		fmt.Printf("Recursion available flag mismatch: IANA %s vs Yeti %s\n",
			strconv.FormatBool(iana.RecursionAvailable),
			strconv.FormatBool(yeti.RecursionAvailable))
		equivalent = false
	}
	if iana.AuthenticatedData != yeti.AuthenticatedData {
		fmt.Printf("Authenticated data flag mismatch: IANA %s vs Yeti %s\n",
			iana.AuthenticatedData, yeti.AuthenticatedData)
		equivalent = false
	}
	if iana.CheckingDisabled != yeti.CheckingDisabled {
		fmt.Printf("Checking disabled flag mismatch: IANA %s vs Yeti %s\n",
			iana.CheckingDisabled, yeti.CheckingDisabled)
		equivalent = false
	}
	if iana.Rcode != yeti.Rcode {
		fmt.Printf("Rcode mismatch: IANA %s vs Yeti %s\n",
			dns.RcodeToString[iana.Rcode],
			dns.RcodeToString[yeti.Rcode])
		equivalent = false
	}
	if (len(iana.Question) != 1) || (len(yeti.Question) != 1) {
		fmt.Printf("Bogus number of questions: IANA %d, Yeti %d\n",
			len(iana.Question), len(yeti.Question))
		equivalent = false
	} else {
		if iana.Question[0] != yeti.Question[0] {
			fmt.Printf("Question mismatch: IANA %s vs Yeti %s\n",
				iana.Question[0], yeti.Question[0])
			equivalent = false
		}
	}
	iana_only, yeti_only := compare_rrset(iana.Answer, yeti.Answer)
	if (len(iana_only) > 0) || (len(yeti_only) > 0) {
		equivalent = false
		if len(iana_only) > 0 {
			fmt.Print("Answer section, IANA only\n")
			for _, rr := range(iana_only) {
				fmt.Printf("%s\n", rr)
			}
		}
		if len(yeti_only) > 0 {
			fmt.Print("Answer section, Yeti only\n")
			for _, rr := range(yeti_only) {
				fmt.Printf("%s\n", rr)
			}
		}
	}
	iana_only, yeti_only = compare_rrset(iana.Ns, yeti.Ns)
	if (len(iana_only) > 0) || (len(yeti_only) > 0) {
		equivalent = false
		if len(iana_only) > 0 {
			fmt.Print("Authority section, IANA only\n")
			for _, rr := range(iana_only) {
				fmt.Printf("%s\n", rr)
			}
		}
		if len(yeti_only) > 0 {
			fmt.Print("Authority section, Yeti only\n")
			for _, rr := range(yeti_only) {
				fmt.Printf("%s\n", rr)
			}
		}
	}
	if equivalent {
//		fmt.Print("Equivalent. Yay!\n")
	} else {
//		fmt.Printf("---[ IANA ]----\n%s\n---[ Yeti ]----\n%s\n",
//			iana, yeti)
//		os.Exit(0)
	}
}

func yeti_query(srvs *yeti_server_set, iana_query *dns.Msg, iana_resp *dns.Msg) {
	// TODO: perform in background
	for _, ip := range srvs.next() {
		server := "[" + ip.String() + "]:53"
		fmt.Printf("Sending query to %s...", server)
		os.Stdout.Sync()
		yeti_resp, qtime, err := dnsstub.DnsQuery(server, iana_query)
		fmt.Printf("done. (%s)\n", qtime)
		if err != nil {
			// XXX: fix error handling
			fmt.Printf("Error querying Yeti root server; %s\n", err)
		} else {
			compare_resp(iana_resp, yeti_resp)
		}
	}
}

// Main function.
// TODO: verbose/debug flags
func main() {
	ips := make([]net.IP, 0, 0)
	if len(os.Args) > 1 {
		for _, server := range os.Args[1:] {
			ip := net.ParseIP(server)
			// TODO: allow host name here
			if ip == nil {
				log.Fatalf("Unrecognized IP address '%s'\n",
					server)
			}
			if ip.To4() != nil {
				log.Printf("WARNING: IP address '%s' is not an IPv6 address\n",
					ip)
			}
			ips = append(ips, ip)
		}
	}
	servers := init_yeti_server_set("round-robin", ips)
	servers.algorithm = "random"
	for {
		y, err := read_next_message()
		if (err != nil) && (err != io.EOF) {
			log.Fatal(err)
		}
		if y == nil {
			break
		}
		yeti_query(servers, y.query, y.answer)
		// TODO: look up Yeti root servers periodically (re-priming)
	}
}
