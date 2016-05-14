package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"github.com/miekg/dns"
	"github.com/miekg/pcap"
)

var (
	resolv_conf	*dns.ClientConfig
)

type stub_resolve_result struct {
	ownername	string
	answer		*dns.Msg
}

func stub_resolve(ownername string, rtype uint16,
                  results chan<- stub_resolve_result) {
	var result stub_resolve_result
	result.ownername = ownername
	dnsClient := new(dns.Client)
	dnsClient.Net = "tcp"
	query := new(dns.Msg)
	query.RecursionDesired = true
	query.SetQuestion(ownername, rtype)
	for _, server := range resolv_conf.Servers {
		resolver := server + ":53"
		r , _, err := dnsClient.Exchange(query, resolver)
		if (err == nil) && (r != nil) && (r.Rcode == dns.RcodeSuccess) {
			result.answer = r
			results <- result
			return
		}
	}
	result.answer = nil
	results <- result
}

func get_root_server_addresses() (map[[4]byte]bool, map[[16]byte]bool) {
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
	results := make(chan stub_resolve_result, len(root_servers))
	for _, ns := range root_servers {
		go stub_resolve(ns, dns.TypeAAAA, results)
		go stub_resolve(ns, dns.TypeA, results)
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
				copy(a[:], net.ParseIP(a_s)[0:4])
				root_addresses4[a] = true
			}
		}
	}
	return root_addresses4, root_addresses6
}

func pcap2ymmv(fname string,
               root_addresses4 map[[4]byte]bool,
               root_addresses6 map[[16]byte]bool) {
	file, err := os.Open(fname)
	if err != nil {
		log.Fatal(err)
	}
	pcap_file, err := pcap.NewReader(file)
	if err != nil {
		log.Fatal(err)
	}

	for {
		pkt := pcap_file.Next()
		if pkt == nil {
			break
		}
		pkt.Decode()
		bogus := false
		for _, hdr := range pkt.Headers {
			switch hdr.(type) {
			case *pcap.Iphdr:
				// verify that this is an IPv6 packet
				iphdr := hdr.(*pcap.Iphdr)
				if iphdr.Version != 6 {
					bogus = true
					break
				}
				// check that it is from one of our
				// desired addresses
				var addr [16]byte
				copy(addr[:], iphdr.SrcIp[0:16])
				_, found :=  root_addresses6[addr]
				if !found {
					bogus = true
					break
				}
			case *pcap.Udphdr:
				udphdr := hdr.(*pcap.Udphdr)
				if udphdr.SrcPort != 53 {
					bogus = true
					break
				}
			}
		}
		if !bogus {
			fmt.Printf("Matched a packet!\n")
		}
	}
	file.Close()
}

func main() {
	// initialize our stub resolver
	var ( err error )
	resolv_conf, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		log.Fatal(err)
	}

	root_addresses4, root_addresses6 := get_root_server_addresses()
	for _, fname := range os.Args[1:] {
		pcap2ymmv(fname, root_addresses4, root_addresses6)
	}
}
