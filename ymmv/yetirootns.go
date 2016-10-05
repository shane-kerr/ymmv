package main

import (
	"github.com/miekg/dns"
	"github.com/shane-kerr/ymmv/dnsstub"
	"log"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

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
	if ttl > MAX_TTL {
		ttl = MAX_TTL
	}
	result := time.Second * time.Duration(ttl+1)
	return result
}

// information about each IP address for each Yeti name server
type ip_info struct {
	// IP address
	ip net.IP
	// smoothed round-trip time (SRTT) for this IP address
	srtt time.Duration
}

// information about each Yeti name server
type ns_info struct {
	// name of the name server, like "bii.dns-lab.net" (may be "")
	name string

	// IP addresses of the name server
	ip_info []ip_info

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

	// make a set of IP information, copying old SRTT if present in the old set
	var new_ip_info []ip_info
	for _, ip := range new_ip {
		found := false
		for _, info := range ns.ip_info {
			if ip.Equal(info.ip) {
				dbg.Printf("%s: copying old IP information ip=%s, srtt=%s", ns.name, info.ip, info.srtt)
				new_ip_info = append(new_ip_info, info)
				found = true
				break
			}
		}
		if !found {
			dbg.Printf("%s: adding new IP information ip=%s, srtt=0", ns.name, ip)
			new_ip_info = append(new_ip_info, ip_info{ip: ip, srtt: 0})
		}
	}

	ns.srvs.lock.Lock()
	ns.ip_info = new_ip_info
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
		var ns_ip_info []ip_info
		for _, ip := range ips {
			ns_ip_info = append(ns_ip_info, ip_info{ip: ip, srtt: 0})
		}
		srvs.ns = append(srvs.ns, &ns_info{ip_info: ns_ip_info})
	}

	srvs.algorithm = "round-robin"
	srvs.next_server = 0
	srvs.next_ip = 0

	return srvs
}

type query_target struct {
	// information about IP to query
	ip_info *ip_info
	// server to update with SRTT information
	ns_info *ns_info
}

// Get the next set of IP addresses to query.
// For most algorithms this is a single address, but it may be more (for "all").
func (srvs *yeti_server_set) next() (targets []query_target) {
	srvs.lock.Lock()
	defer srvs.lock.Unlock()

	if srvs.algorithm == "round-robin" {
		for srvs.next_ip >= len(srvs.ns[srvs.next_server].ip_info) {
			srvs.next_server = (srvs.next_server + 1) % len(srvs.ns)
			srvs.next_ip = 0
		}
		ns := srvs.ns[srvs.next_server]
		ip := &ns.ip_info[srvs.next_ip]
		targets = append(targets, query_target{ip_info: ip, ns_info: ns})
		srvs.next_ip = srvs.next_ip + 1
	} else if srvs.algorithm == "rtt" {
		log.Fatalf("rtt-based server selection unimplemented")
	} else {
		var all_targets []query_target
		for _, ns := range srvs.ns {
			for _, ip := range ns.ip_info {
				all_targets = append(all_targets, query_target{ip_info: &ip, ns_info: ns})
			}
		}
		if srvs.algorithm == "all" {
			targets = all_targets
		} else if srvs.algorithm == "random" {
			targets = append(targets, all_targets[rand.Intn(len(all_targets))])
		}
	}
	return targets
}

type yeti_server_generator struct {
	servers *yeti_server_set
	targets chan []query_target
}

func init_yeti_server_generator(algorithm string, ips []net.IP) (gen *yeti_server_generator) {
	gen = new(yeti_server_generator)
	gen.servers = init_yeti_server_set(ips)
	gen.servers.algorithm = algorithm
	gen.targets = make(chan []query_target)
	go func() {
		for {
			gen.targets <- gen.servers.next()
		}
	}()
	return gen
}

func (gen *yeti_server_generator) next() (targets []query_target) {
	return <-gen.targets
}
