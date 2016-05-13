package main

import (
	"fmt"
	"log"
	"os"
	"github.com/miekg/dns"
	"github.com/miekg/pcap"
)

var (
	resolv_conf	*dns.ClientConfig
)

func stub_resolve(ownername string, rtype uint16, results chan<- *dns.Msg) {
	dnsClient := new(dns.Client)
	dnsClient.Net = "tcp"
	query := new(dns.Msg)
	query.RecursionDesired = true
	query.SetQuestion(ownername, rtype)
	for _, server := range resolv_conf.Servers {
		resolver := server + ":53"
		r , _, err := dnsClient.Exchange(query, resolver)
		if (err == nil) && (r != nil) && (r.Rcode == dns.RcodeSuccess) {
			results <- r
			return
		}
	}
	// TODO: send the name of the failed lookup also
	results <- nil
}

func get_yeti_server_addresses() []string {
	// ask the Yeti root servers what the Yeti root servers are
	dnsClient := new(dns.Client)
	dnsClient.Net = "tcp"
	query := new(dns.Msg)
	query.SetQuestion(".", dns.TypeNS)
	// TODO: make a list of servers to query, instead of hard-coded
	response, _, err := dnsClient.Exchange(query, "bii.dns-lab.net:53")
	if err != nil {
		log.Fatal(err)
	}
	// TODO: DNSSEC validate answer
	var root_servers []string
	for _, root_server := range response.Answer {
		switch root_server.(type) {
		case *dns.NS:
			ns := root_server.(*dns.NS).Ns
			root_servers = append(root_servers, ns)
		}
	}
	// look up the IPv6 address of the Yeti servers
	results := make(chan *dns.Msg, len(root_servers))
	for _, ns := range root_servers {
		go stub_resolve(ns, dns.TypeAAAA, results)
	}
	var yeti_addresses []string
	for _ = range root_servers {
		response := <-results
		if response == nil {
			log.Fatal("Error looking up root server")
		}
		for _, yeti_address := range response.Answer {
			switch yeti_address.(type) {
			case *dns.AAAA:
				aaaa := yeti_address.(*dns.AAAA).AAAA.String()
				yeti_addresses = append(yeti_addresses, aaaa)
			}
		}
	}
	return yeti_addresses
}

func pcap2ymmv(fname string, yeti_addresses []string) {
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
		fmt.Printf("got a packet\n")
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

	yeti_addresses := get_yeti_server_addresses()
	fmt.Printf("%s\n", yeti_addresses)
	for _, fname := range os.Args[1:] {
		pcap2ymmv(fname, yeti_addresses)
	}
}
