package main

import (
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/miekg/dns"
	"github.com/shane-kerr/ymmv/dnsstub"
	"log"
	"net"
	"os"
	"time"
)

const REPLY_TIMEOUT = time.Hour

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

// Lookup all of the IP addresses associated with the root name servers.
// Return two maps based on the results found, which have the keys of
// the binary values of the IPv4 and IPv6 addresses. (It's a bit clumsy,
// but it allows us to do quick and easy lookups of the addresses in the
// pcap later.)
func lookup_root_server_addresses() map[string]bool {
	if debug {
		fmt.Fprintf(os.Stderr, "pcap2ymmv lookup_root_server_addresses()\n")
	}

	// set up a resolver
	resolver, err := dnsstub.Init(4, nil)
	if err != nil {
		log.Fatalf("Error setting up DNS stub resolver: %s\n", err)
	}

	// look up the NS of the IANA root
	root_ns, _, err := resolver.SyncQuery(".", dns.TypeNS)
	if err != nil {
		log.Fatalf("Error looking up NS for root: %s\n", err)
	}

	// look up the A and AAAA records of each root name server
	var root_servers []string
	for _, root_server := range root_ns.Answer {
		switch root_server.(type) {
		case *dns.NS:
			ns := root_server.(*dns.NS).Ns
			root_servers = append(root_servers, ns)
			resolver.AsyncQuery(ns, dns.TypeAAAA)
			resolver.AsyncQuery(ns, dns.TypeA)
		}
	}

	root_addresses := make(map[string]bool)
	for i := 0; i < len(root_servers)*2; i++ {
		response, _, qname, qtype, err := resolver.Wait()
		if err != nil {
			log.Fatalf("Error looking up %s %s: %s", qname, dns.TypeToString[qtype], err)
		}
		for _, root_address := range response.Answer {
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
	return root_addresses
}

func ymmv_write(ip_family int, addr net.IP,
	query_time time.Time, query *dns.Msg, answer_time time.Time, answer *dns.Msg) {
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

	// output when the query happened
	seconds := uint32(query_time.Unix())
	err = binary.Write(os.Stdout, binary.BigEndian, seconds)
	if err != nil {
		log.Fatal(err)
	}
	nanoseconds := uint32(query_time.Nanosecond())
	err = binary.Write(os.Stdout, binary.BigEndian, nanoseconds)
	if err != nil {
		log.Fatal(err)
	}

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
	seconds = uint32(answer_time.Unix())
	err = binary.Write(os.Stdout, binary.BigEndian, seconds)
	if err != nil {
		log.Fatal(err)
	}
	nanoseconds = uint32(answer_time.Nanosecond())
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

type sent_pkt_info struct {
	when     time.Time
	src_ip   net.IP
	src_port uint16
	dst_ip   net.IP
	dst_port uint16
	msg      *dns.Msg
}

func make_key(pi *sent_pkt_info, is_query bool) string {
	if is_query {
		return fmt.Sprintf("%s|%d|%s|%d|%d", pi.src_ip, pi.src_port, pi.dst_ip, pi.dst_port, pi.msg.Id)
	} else {
		return fmt.Sprintf("%s|%d|%s|%d|%d", pi.dst_ip, pi.dst_port, pi.src_ip, pi.src_port, pi.msg.Id)
	}
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

	pkt_sent := make(map[string]*sent_pkt_info)

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

		ip_match := false
		var ip_family int
		var is_query bool
		var pkt_info *sent_pkt_info

		//  parse our packet information
		packet := gopacket.NewPacket(pkt_bytes, pcap_file.LinkType(), gopacket.Default)
		if packet == nil {
			fmt.Fprintf(os.Stderr, "pcap2ymmv unable to parse packet\n")
			continue
		}

		// filter based on our IP addresses
		ipv6, _ := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
		if ipv6 != nil {
			ip_family = 6
			if debug {
				fmt.Fprintf(os.Stderr, "pcap2ymmv IPv6 %s -> %s\n", ipv6.SrcIP, ipv6.DstIP)
			}
			pkt_info = &sent_pkt_info{when: ci.Timestamp, src_ip: ipv6.SrcIP, dst_ip: ipv6.DstIP}
			// if the destination IP address is one of our targets, this is a query
			is_query = true
			_, ip_match = root_addresses[ipv6.DstIP.String()]
			if !ip_match {
				// if the source IP address is one of our targets, this is an answer
				is_query = false
				_, ip_match = root_addresses[ipv6.SrcIP.String()]
			}
		} else {
			ipv4, _ := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			if ipv4 == nil {
				if debug {
					fmt.Fprintf(os.Stderr, "pcap2ymmv packet is neither IPv4 nor IPv6\n")
				}
				continue
			}
			ip_family = 4
			if debug {
				fmt.Fprintf(os.Stderr, "pcap2ymmv IPv4 %s -> %s\n", ipv4.SrcIP.String(), ipv4.DstIP.String())
			}
			pkt_info = &sent_pkt_info{when: ci.Timestamp, src_ip: ipv4.SrcIP, dst_ip: ipv4.DstIP}
			// if the destination IP address is one of our targets, this is a query
			is_query = true
			_, ip_match = root_addresses[ipv4.DstIP.String()]
			if !ip_match {
				// if the source IP address is one of our targets, this is an answer
				is_query = false
				_, ip_match = root_addresses[ipv4.SrcIP.String()]
			}
		}
		if debug {
			fmt.Fprintf(os.Stderr, "pcap2ymmv IP match %t, query %t\n", ip_match, is_query)
		}
		if !ip_match {
			continue
		}

		// filter based on port 53
		udp, _ := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if udp == nil {
			fmt.Fprintf(os.Stderr, "pcap2ymmv unable to parse UDP packet\n")
			continue
		}
		if debug {
			fmt.Fprintf(os.Stderr, "pcap2ymmv UDP port src:%d, dst:%d\n", udp.SrcPort, udp.DstPort)
		}
		if is_query {
			if udp.DstPort != 53 {
				continue
			}
		} else {
			if udp.SrcPort != 53 {
				continue
			}
		}
		pkt_info.src_port = uint16(udp.SrcPort)
		pkt_info.dst_port = uint16(udp.DstPort)

		// if we got a valid IP and UDP packet, process it
		if debug {
			fmt.Fprintf(os.Stderr, "pcap2ymmv matched packet, is_query:%t\n", is_query)
		}

		// parse the DNS packet
		pkt_info.msg = new(dns.Msg)
		err = pkt_info.msg.Unpack(udp.Payload)
		if (err != nil) && (err != dns.ErrTruncated) {
			fmt.Fprintf(os.Stderr, "pcap2ymmv error unpacking DNS message: %s\n", err)
			continue
		}

		// actually process the query
		key := make_key(pkt_info, is_query)
		if is_query {
			pkt_sent[key] = pkt_info
		} else {
			sent_pkt_info, ok := pkt_sent[key]
			if ok {
				ymmv_write(ip_family, pkt_info.src_ip,
					sent_pkt_info.when, sent_pkt_info.msg, pkt_info.when, pkt_info.msg)
				delete(pkt_sent, key)
			} else {
				fmt.Fprintf(os.Stderr, "reply without sent message %s\n", key)
			}
		}

		// check packets and delete very old ones
		for key, value := range pkt_sent {
			if time.Since(value.when) > REPLY_TIMEOUT {
				fmt.Fprintf(os.Stderr, "no reply in %s for sent message %s\n", time.Since(value.when), key)
				delete(pkt_sent, key)
			}
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
