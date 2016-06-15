// TODO: IPv4 parsing?
// TODO: use dnsstub library
// TODO: match outbound to inbound queries
package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/miekg/dns"
	"log"
	"net"
	"os"
	"time"
)

var (
	// We store the configuration of our local resolver in a global
	// variable for convenience.
	resolv_conf *dns.ClientConfig

	// Use a global debug flag.
	debug bool
)

// If we were passed name server addresses, parse them with this function.
func parse_root_server_addresses(addrs []string) map[string]bool {
	if debug {
		fmt.Fprintf(os.Stderr, "pcap2ymmv parse_root_server_addresses()\n")
		fmt.Fprintf(os.Stderr, "pcap2ymmv addrs:%s\n", addrs)
	}
	root_addresses := make(map[string]bool)
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			log.Fatal("Error parsing address '%s'", addr)
		}
		root_addresses[ip.String()] = true
		if debug {
			fmt.Fprintf(os.Stderr, "pcap2ymmv checking for %s\n", ip.String())
		}
	}
	return root_addresses
}

// We have a goroutine to act as a stub resolver, and use this
// structure to send the question in and get the results out.
type stub_resolve_info struct {
	ownername string
	rtype     uint16
	answer    *dns.Msg
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
			r, _, err := dnsClient.Exchange(query, resolver)
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
func lookup_root_server_addresses() map[string]bool {
	if debug {
		fmt.Fprintf(os.Stderr, "pcap2ymmv lookup_root_server_addresses()\n")
	}
	// look up the NS of the IANA root
	root_client := new(dns.Client)
	root_client.Net = "tcp"
	ns_query := new(dns.Msg)
	ns_query.SetQuestion(".", dns.TypeNS)
	// TODO: avoid hard-coding a particular root server here
	ns_response, _, err := root_client.Exchange(ns_query,
		"f.root-servers.net:53")
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
	for i := 0; i < 8; i++ {
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
	root_addresses := make(map[string]bool)
	for i := 0; i < len(root_servers)*2; i++ {
		response := <-results
		if response.answer == nil {
			log.Fatalf("Error looking up root server %s",
				response.ownername)
		}
		for _, root_address := range response.answer.Answer {
			switch root_address.(type) {
			case *dns.AAAA:
				aaaa_s := root_address.(*dns.AAAA).AAAA.String()
				if debug {
					fmt.Fprintf(os.Stderr, "pcap2ymmv IANA server: %s\n", aaaa_s)
				}
				root_addresses[aaaa_s] = true
			case *dns.A:
				a_s := root_address.(*dns.A).A.String()
				if debug {
					fmt.Fprintf(os.Stderr, "pcap2ymmv IANA server: %s\n", a_s)
				}
				root_addresses[a_s] = true
			}
		}
	}
	close(questions)
	return root_addresses
}

func ymmv_write(ip_family int, addr net.IP, query dns.Msg,
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
		log.Fatalf("Unknown ip_family %d\n", ip_family)
	}
	if err != nil {
		log.Fatal(err)
	}

	// output (U)DP or (T)CP
	_, err = os.Stdout.Write([]byte("u")) // only support UDP for now...
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
	seconds := uint32(answer_time.Unix())
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

	// write our answer
	_, err = os.Stdout.Write(answer_bytes)
	if err != nil {
		log.Fatal(err)
	}
	os.Stdout.Sync()

	if debug {
		fmt.Fprintf(os.Stderr, "pcap2ymmv wrote ymmv record of %d bytes\n", len(answer_bytes))
	}
}

func parse_query(raw_answer []byte) (*dns.Msg, *dns.Msg, error) {
	// parse the query
	answer := new(dns.Msg)
	err := answer.Unpack(raw_answer)
	if err != nil {
		return nil, nil, err
	}
	answer.Id = 0
	// infer the answer and build that
	query := answer.Copy()
	query.Response = false
	query.Authoritative = false
	query.Truncated = false
	query.AuthenticatedData = true
	query.CheckingDisabled = true
	query.Rcode = 0
	query.Answer = nil
	query.Ns = nil
	query.Extra = nil
	return query, answer, nil
}

// Look in the named file and find any packets that are from our root
// servers on port 53.
func pcap2ymmv(fname string, root_addresses map[string]bool) {
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
	pcap_file, err := pcapgo.NewReader(file)
	if err != nil {
		log.Fatal(err)
	}

	for {
		// reach each packet
		pkt_bytes, ci, err := pcap_file.ReadPacketData()
		if err != nil {
			fmt.Fprintf(os.Stderr, "pcap2ymmv error reading packet; %s\n", err)
			break
		}
		if debug {
			fmt.Fprintf(os.Stderr, "pcap2ymmv read packet (len:%d)\n", len(pkt_bytes))
		}

		// check for match against IP addresses that we care about
		ip_match := false
		var ip_family int
		var ip_addr net.IP
		var udp *layers.UDP
		ipv6packet := gopacket.NewPacket(pkt_bytes, layers.LayerTypeIPv6, gopacket.Default)
		var ipv6 *layers.IPv6
		if ipv6packet != nil {
			ipv6, _ = ipv6packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			//			ipv6, _ = ipv6Layer.(*layers.IPv6)
		}
		if ipv6 != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "pcap2ymmv IPv6 %s\n", ipv6.SrcIP.String())
			}
			ip_family = 6
			ip_addr = ipv6.SrcIP
			_, ip_match = root_addresses[ipv6.SrcIP.String()]
			if ip_match {
				udp, _ = ipv6packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
			}
		} else {
			ipv4packet := gopacket.NewPacket(pkt_bytes, layers.LayerTypeIPv4, gopacket.Default)
			var ipv4 *layers.IPv4
			if ipv4packet != nil {
				ipv4, _ = ipv4packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
				//				ipv4, _ = ipv4Layer.(*layers.IPv4)
			}
			if ipv4 != nil {
				if debug {
					fmt.Fprintf(os.Stderr, "pcap2ymmv IPv4 %s\n", ipv4.SrcIP.String())
				}
				ip_family = 4
				ip_addr = ipv4.SrcIP
				_, ip_match = root_addresses[ipv4.SrcIP.String()]
				if ip_match {
					udp, _ = ipv4packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
				}
			}
		}
		if debug {
			fmt.Fprintf(os.Stderr, "pcap2ymmv IP match %t\n", ip_match)
		}
		if !ip_match {
			continue
		}

		// we only want port 53
		if debug {
			fmt.Fprintf(os.Stderr, "pcap2ymmv UDP port: %d\n", udp.SrcPort)
		}
		if udp.SrcPort != 53 {
			continue
		}

		// if we got a valid IP and UDP packet, process it
		if debug {
			fmt.Fprintf(os.Stderr, "pcap2ymmv matched packet\n")
		}

		// parse the payload as the DNS message
		query, answer, err := parse_query(udp.Payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "pcap2ymmv error unpacking DNS message: %s\n", err)
		} else {
			ymmv_write(ip_family, ip_addr, *query, ci.Timestamp, *answer)
			os.Stdout.Sync()
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
	var (
		err error
	)
	resolv_conf, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		log.Fatal(err)
	}

	// get root server addresses
	var root_addresses map[string]bool
	if len(os.Args) > 1 {
		root_addresses = parse_root_server_addresses(os.Args[1:])
	} else {
		root_addresses = lookup_root_server_addresses()
	}

	// process stdin as a pcap file
	pcap2ymmv("-", root_addresses)
}
