package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"time"
	"github.com/miekg/dns"
	"github.com/shane-kerr/ymmv/dnsstub"
)

type ymmv_message struct {
	ip_family	byte
	ip_protocol	byte
	addr		*net.IP
	query_time	time.Time
	query		*dns.Msg
	answer_time	time.Time
	answer		*dns.Msg
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
	id, err := dnsstub.RandUint16()
	if err != nil {
		log.Fatalf("Error generating random query ID; %s", err)
	}
	ns_query.Id = id
	// TODO: avoid hard-coding a particular root server here
	ns_response, _, err := root_client.Exchange(ns_query,
						    "yeti-ns.wide.ad.jp.:53")
	if err != nil {
		log.Fatalf("Error looking up Yeti root server NS; %s", err)
	}

	// lookup the addresses of some of our Yeti servers
	resolver, err := dnsstub.Init(16)
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
		answer, qname, _, err := resolver.Wait()
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
	algorithm string
	ips []net.IP
	rtt_msec []int
	next_server int
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
	srvs.rtt_msec = make([]int, len(srvs.ips), len(srvs.ips))
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

func yeti_query(srvs *yeti_server_set, query *dns.Msg) (result *dns.Msg, err error) {
	for _, ip := range srvs.next() {
		client := new(dns.Client)
		id, err := dnsstub.RandUint16()
		if err != nil {
			log.Fatalf("Error generating random query ID; %s", err)
		}
		new_query := *query
		new_query.Id = id
//		resp, qtime, err := client.Exchange(&new_query, "["+ip.String()+"]:53")
		_, _, err = client.Exchange(&new_query, "["+ip.String()+"]:53")
		if err != nil {
			// XXX: fix error handling
			fmt.Printf("Error querying Yeti root server; %s\n", err)
		}
	}
	return nil, nil
}

// Main function.
func main() {
	ips := make([]net.IP, 0, 0)
	if len(os.Args) > 1 {
		for _, server := range os.Args[1:] {
			ip := net.ParseIP(server)
			if ip == nil {
				log.Fatalf("Unrecognized IP address '%s'\n",
					   server)
			}
			if ip.To4() != nil {
				log.Fatalf("IP address '%s' is not an IPv6 address\n",
					   ip)
			}
			ips = append(ips, ip)
		}
	}
	servers := init_yeti_server_set("round-robin", ips)
	servers.algorithm = "random"
	for {
		y , err := read_next_message()
		if (err != nil) && (err != io.EOF) {
			log.Fatal(err)
		}
		if y == nil {
			break
		}
		yeti_query(servers, y.query)
	}
}

