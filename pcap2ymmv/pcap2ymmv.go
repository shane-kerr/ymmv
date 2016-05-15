package main

import (
	"fmt"
	"encoding/binary"
	"log"
	"net"
	"os"
	"time"
	"github.com/miekg/dns"
	"github.com/miekg/pcap"
)

var (
	// We store the configuration of our local resolver in a global
	// variable for convenience.
	resolv_conf	*dns.ClientConfig

	// Use a global debug flag.
	debug		bool
)

// If we were passed name server addresses, parse them with this function.
func parse_root_server_addresses(addrs []string)(map[[4]byte]bool, map[[16]byte]bool) {
	if debug {
		fmt.Fprintf(os.Stderr, "parse_root_server_addresses()\n")
		fmt.Fprintf(os.Stderr, "addrs:%s\n", addrs)
	}
	root_addresses4 := make(map[[4]byte]bool)
	root_addresses6 := make(map[[16]byte]bool)
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip.To4() == nil {
			// IPv6 address
			var aaaa [16]byte
			copy(aaaa[:], ip[0:16])
			for i, b := range aaaa {
				fmt.Fprintf(os.Stderr, "a  %d:[%s]\n", i, b)
				fmt.Fprintf(os.Stderr, "ip %d:[%s]\n", i, ip[i])
			}
			root_addresses6[aaaa] = true
		} else {
			// IPv4 address
			var a [4]byte
			copy(a[:], ip.To4()[0:4])
			root_addresses4[a] = true
		}
	}
	fmt.Fprintf(os.Stderr, "%s\n" ,root_addresses4)
	return root_addresses4, root_addresses6
}

// We have a goroutine to act as a stub resolver, and use this
// structure to send the question in and get the results out.
type stub_resolve_info struct {
	ownername	string
	rtype		uint16
	answer		*dns.Msg
}

// A goroutine which performs stub lookups from a queue, writing
// the results to another queue.
func stub_resolve(questions <-chan stub_resolve_info,
                  results chan<- stub_resolve_info) {
	// make a client for our lookups
	dnsClient := new(dns.Client)
	dnsClient.Net = "tcp"
	// read each question on our channel
	for question := range questions {
		// build our answer
		var result stub_resolve_info = question
		result.answer = nil
		// make a DNS query based on our question
		query := new(dns.Msg)
		query.RecursionDesired = true
		query.SetQuestion(question.ownername, question.rtype)
		// check each resolver in turn
		for _, server := range resolv_conf.Servers {
			resolver := server + ":53"
			r , _, err := dnsClient.Exchange(query, resolver)
			// if we got an answer, use that and stop trying
			if (err == nil) && (r != nil) && (r.Rcode == dns.RcodeSuccess) {
				result.answer = r
				break
			}
		}
		// send back our answer (might be nil)
		results <- result
	}
}

// Lookup all of the IP addresses associated with the root name servers.
// Return two maps based on the results found, which have the keys of
// the binary values of the IPv4 and IPv6 addresses. (It's a bit clumsy,
// but it allows us to do quick and easy lookups of the addresses in the
// pcap later.)
func lookup_root_server_addresses() (map[[4]byte]bool, map[[16]byte]bool) {
	if debug {
		fmt.Fprintf(os.Stderr, "lookup_root_server_addresses()\n")
	}
	// look up the NS of the IANA root
	root_client := new(dns.Client)
	root_client.Net = "tcp"
	ns_query := new(dns.Msg)
	ns_query.SetQuestion(".", dns.TypeNS)
	// TODO: avoid hard-coding a particular root server here
	ns_response , _, err := root_client.Exchange(ns_query,
                                                     "k.root-servers.net:53")
	if err != nil {
		log.Fatal("Error looking up root name servers")
	}
	var root_servers []string
	for _, root_server := range ns_response.Answer {
		switch root_server.(type) {
		case *dns.NS:
			ns := root_server.(*dns.NS).Ns
			root_servers = append(root_servers, ns)
		}
	}
	// look up the addresses of the root servers
	questions := make(chan stub_resolve_info, 16)
	results := make(chan stub_resolve_info, len(root_servers)*2)
	for i := 0; i<8; i++ {
		go stub_resolve(questions, results)
	}
	for _, ns := range root_servers {
		info := new(stub_resolve_info)
		info.ownername = ns
		info.rtype = dns.TypeAAAA
		questions <- *info
		info = new(stub_resolve_info)
		info.ownername = ns
		info.rtype = dns.TypeA
		questions <- *info
	}
	root_addresses4 := make(map[[4]byte]bool)
	root_addresses6 := make(map[[16]byte]bool)
	for i := 0; i<len(root_servers)*2; i++ {
		response := <-results
		if response.answer == nil {
			log.Fatal("Error looking up root server %s",
			          response.ownername)
		}
		for _, root_address := range response.answer.Answer {
			switch root_address.(type) {
			case *dns.AAAA:
				aaaa_s := root_address.(*dns.AAAA).AAAA.String()
				var aaaa [16]byte
				copy(aaaa[:], net.ParseIP(aaaa_s)[0:16])
				root_addresses6[aaaa] = true
			case *dns.A:
				a_s := root_address.(*dns.A).A.String()
				var a [4]byte
				copy(a[:], net.ParseIP(a_s).To4()[0:4])
				root_addresses4[a] = true
			}
		}
	}
	close(questions)
	return root_addresses4, root_addresses6
}

func ymmv_write(ip_family int, addr []byte, query dns.Msg,
		answer_time time.Time, answer dns.Msg) {
	// output magic value
	_, err := os.Stdout.Write([]byte("ymmv"))
	if err != nil {
		log.Fatal(err)
	}

	// output address family
	if ip_family == 4 {
		_, err = os.Stdout.Write([]byte("4"))
	} else if ip_family == 6 {
		_, err = os.Stdout.Write([]byte("6"))
	} else {
		log.Fatal("Unknown ip_family %d\n", ip_family)
	}
	if err != nil {
		log.Fatal(err)
	}

	// output (U)DP or (T)CP
	_, err = os.Stdout.Write([]byte("u"))	// only support UDP for now...
	if err != nil {
		log.Fatal(err)
	}

	// output actual address
	_, err = os.Stdout.Write(addr)
	if err != nil {
		log.Fatal(err)
	}

	// output when the query happened (we don't know, so use 0)
	_, err = os.Stdout.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})

	// write the byte count of our query
	query_bytes, err := query.Pack()
	if err != nil {
		log.Fatal(err)
	}
	query_len := uint16(len(query_bytes))
	err = binary.Write(os.Stdout, binary.BigEndian, query_len)
	if err != nil {
		log.Fatal(err)
	}

	// write our query
	_, err = os.Stdout.Write(query_bytes)
	if err != nil {
		log.Fatal(err)
	}

	// output when the answer arrived
	seconds := uint32(answer_time.Second())
	err = binary.Write(os.Stdout, binary.BigEndian, seconds)
	if err != nil {
		log.Fatal(err)
	}
	nanoseconds := uint32(answer_time.Nanosecond())
	err = binary.Write(os.Stdout, binary.BigEndian, nanoseconds)
	if err != nil {
		log.Fatal(err)
	}

	// write the byte count of our answer
	answer_bytes, err := answer.Pack()
	if err != nil {
		log.Fatal(err)
	}
	answer_len := uint16(len(answer_bytes))
	err = binary.Write(os.Stdout, binary.BigEndian, answer_len)
	if err != nil {
		log.Fatal(err)
	}

	// write our query
	_, err = os.Stdout.Write(answer_bytes)
	if err != nil {
		log.Fatal(err)
	}

	// XXX: do we need to flush?
}

// Look in the named file and find any packets that are from our root
// servers on port 53.
func pcap2ymmv(fname string,
               root_addresses4 map[[4]byte]bool,
               root_addresses6 map[[16]byte]bool) {
	// open our pcap file
	var file *os.File
	if fname == "-" {
		file = os.Stdin
	} else {
		named_file, err := os.Open(fname)
		if err != nil {
			log.Fatal(err)
		}
		file = named_file
	}
	pcap_file, err := pcap.NewReader(file)
	if err != nil {
		log.Fatal(err)
	}

	for {
		// reach each packet
		pkt := pcap_file.Next()
		if pkt == nil {
			break
		}
		pkt.Decode()

		// parse each header so we can see if we want this packet
		ip_family := 0
		var ip_addr []byte
		valid_udp := false
		for _, hdr := range pkt.Headers {
			switch hdr.(type) {
			case *pcap.Iphdr:
				// check that the packet comes from one
				// of the addresses that we are looking for
				iphdr := hdr.(*pcap.Iphdr)
				var addr [4]byte
				copy(addr[:], iphdr.SrcIp[0:4])
				_, found :=  root_addresses4[addr]
				if found {
					ip_family = 4
					ip_addr = make([]byte, 4)
					copy(ip_addr[:], addr[0:4])
				}
			case *pcap.Ip6hdr:
				iphdr := hdr.(*pcap.Ip6hdr)
				var addr [16]byte
				copy(addr[:], iphdr.SrcIp[0:16])
				_, found :=  root_addresses6[addr]
				if found {
					ip_family = 6
					ip_addr = make([]byte, 16)
					copy(ip_addr[:], addr[0:16])
				}
			case *pcap.Udphdr:
				udphdr := hdr.(*pcap.Udphdr)
				if udphdr.SrcPort == 53 {
					valid_udp = true
				}
			}
		}

		if (ip_family != 0) && valid_udp {
			answer := new(dns.Msg)
			answer.Unpack(pkt.Payload)
			answer.Id = 0
			query := answer.Copy()
			query.Response = false
			query.Authoritative = false
			query.Truncated = false
			query.AuthenticatedData = true
			query.CheckingDisabled = false
			query.Rcode = 0
			query.Answer = nil
			query.Ns = nil
			old_extra := query.Extra
			query.Extra = nil
			// add our opt section back - probably not really
			// what we want, but what else can we do?
			if old_extra != nil {
				for _, extra := range old_extra {
					switch extra.(type) {
					case *dns.OPT:
						opt := extra.(*dns.OPT)
						query.Extra = []dns.RR{opt}
					}
				}
			}
			ymmv_write(ip_family, ip_addr,
				   *query, pkt.Time, *answer)
		}
	}
	file.Close()
}

// Main function.
func main() {
	// turn on debugging if desired
	if (len(os.Args) > 1) && (os.Args[1] == "-d") {
		debug = true
		os.Args = append(os.Args[:1], os.Args[2:]...)
	}

	// initialize our stub resolver
	var ( err error )
	resolv_conf, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		log.Fatal(err)
	}

	// get root server addresses
	var root_addresses4 map[[4]byte]bool
	var root_addresses6 map[[16]byte]bool
	if len(os.Args) > 1 {
		root_addresses4, root_addresses6 = parse_root_server_addresses(os.Args[1:])
	} else {
		root_addresses4, root_addresses6 = lookup_root_server_addresses()
	}

	// process stdin as a pcap file
	pcap2ymmv("-", root_addresses4, root_addresses6)
}
