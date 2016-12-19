package main

import (
	"github.com/golang/glog"
	"github.com/miekg/dns"
	"github.com/shane-kerr/ymmv/dnsstub"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// starting point to find Yeti root servers
var yeti_root_hints = []string{
	// we use IPv6 literals here, since for some reason the Go
	// net.DialTimeout() function seems to have stopped working
	// for IPv6-only hostnames
	"[240c:f:1:22::6]:53",   // bii.dns-lab.net
	"[2001:200:1d9::35]:53", // yeti-ns.wide.ad.jp
	"[2001:559:8000::6]:53", // yeti-ns.tisf.net
}

// allowed server-selection algorithms
var server_algorithms = map[string]bool{
	"rtt":         true,
	"round-robin": true,
	"random":      true,
	"all":         true,
	"blast":       true,
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
	ip_info []*ip_info

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
			glog.Warningf("Error looking up Yeti root server NS from %s; %s", root, err)
		}
		if ns_response != nil {
			break
		}
	}
	if ns_response == nil {
		glog.Fatalf("Unable to get NS from any Yeti root server")
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
		glog.Fatalf("No NS found for Yeti root")
	}

	// insure our order is repeatable
	sort.Strings(ns_names)

	return ns_names, ns_ttl
}

func refresh_ns(srvs *yeti_server_set) {
	glog.V(1).Infof("refreshing root NS list")

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
	glog.V(1).Infof("refreshing %s", ns.name)

	var new_ip []net.IP
	var this_ttl uint32

	answer, _, err := ns.srvs.resolver.SyncQuery(ns.name, dns.TypeAAAA)
	if err != nil {
		glog.Warningf("Error looking up %s: %s\n", ns.name, err)
	}

	if answer != nil {
		for _, root_address := range answer.Answer {
			switch root_address.(type) {
			case *dns.AAAA:
				aaaa := root_address.(*dns.AAAA).AAAA
				glog.V(2).Infof("AAAA for %s = %s", ns.name, aaaa)
				new_ip = append(new_ip, aaaa)
				this_ttl = root_address.Header().Ttl
			}
		}
	}

	if len(new_ip) == 0 {
		glog.Warningf("No AAAA for %s, checking again in 300 seconds", ns.name)
		this_ttl = 300
	}

	// make a set of IP information, copying old SRTT if present in the old set
	var new_ip_info []*ip_info
	for _, ip := range new_ip {
		found := false
		for _, info := range ns.ip_info {
			if ip.Equal(info.ip) {
				glog.V(1).Infof("%s: copying old IP information ip=%s, srtt=%s", ns.name, info.ip, info.srtt)
				new_ip_info = append(new_ip_info, info)
				found = true
				break
			}
		}
		if !found {
			// if we are updating a name server that already had an IP, warn about this
			if len(ns.ip_info) > 0 {
				glog.Warningf("%s: adding new IP information ip=%s, srtt=0", ns.name, ip)
			}
			new_ip_info = append(new_ip_info, &ip_info{ip: ip, srtt: 0})
		}
	}

	ns.srvs.lock.Lock()
	ns.ip_info = new_ip_info
	when := use_ttl(this_ttl)
	glog.V(1).Infof("scheduling refresh of AAAA for %s in %s\n", ns.name, when)
	ns.timer = time.AfterFunc(when, func() { refresh_aaaa(ns, nil) })
	ns.srvs.lock.Unlock()

	done <- len(new_ip)
}

// get the list of root servers from known Yeti root servers
func yeti_priming(srvs *yeti_server_set) {
	// get the names from the NS RRset
	glog.V(1).Infof("getting root NS RRset")
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
		glog.Fatalf("No AAAA found for Yeti root NS")
	}

	// set timer to refresh our NS RRset
	when := use_ttl(ns_ttl)
	glog.V(1).Infof("scheduling refresh of NS in %s\n", when)
	srvs.root_ns_timer = time.AfterFunc(when, func() { refresh_ns(srvs) })
}

func init_yeti_server_set(ips []net.IP, algo string) (srvs *yeti_server_set) {
	srvs = new(yeti_server_set)

	if len(ips) == 0 {
		glog.Infof("no IP's passed, performing Yeti priming\n")
		var err error
		srvs.resolver, err = dnsstub.Init(4, nil)
		if err != nil {
			glog.Fatalf("Error setting up DNS stub resolver: %s\n", err)
		}
		yeti_priming(srvs)
		glog.V(1).Infof("priming done\n")
	} else {
		var ns_ip_info []*ip_info
		for _, ip := range ips {
			ns_ip_info = append(ns_ip_info, &ip_info{ip: ip, srtt: 0})
		}
		srvs.ns = append(srvs.ns, &ns_info{ip_info: ns_ip_info})
	}

	srvs.algorithm = algo
	srvs.next_server = 0
	srvs.next_ip = 0

	return srvs
}

type query_target struct {
	ip      net.IP
	ns_name string
}

// Get the next set of IP addresses to query.
// For most algorithms this is a single address, but it may be more (for "all").
func (srvs *yeti_server_set) next() (targets []*query_target) {
	srvs.lock.Lock()
	defer srvs.lock.Unlock()

	if srvs.algorithm == "round-robin" {
		for srvs.next_ip >= len(srvs.ns[srvs.next_server].ip_info) {
			srvs.next_server = (srvs.next_server + 1) % len(srvs.ns)
			srvs.next_ip = 0
		}
		ns := srvs.ns[srvs.next_server]
		ip := ns.ip_info[srvs.next_ip].ip
		targets = append(targets, &query_target{ip: ip, ns_name: ns.name})
		srvs.next_ip = srvs.next_ip + 1
	} else if srvs.algorithm == "rtt" {
		var lowest_ip_info *ip_info = nil
		var ns_name string
		for _, ns := range srvs.ns {
			for _, info := range ns.ip_info {
				if (lowest_ip_info == nil) || (lowest_ip_info.srtt > info.srtt) {
					lowest_ip_info = info
					ns_name = ns.name
				}
			}
		}
		targets = append(targets, &query_target{ip: lowest_ip_info.ip, ns_name: ns_name})
	} else if srvs.algorithm == "blast" {
		var low_ip_info [3]*ip_info
		var ns_name [3]string
		for _, ns := range srvs.ns {
			for _, info := range ns.ip_info {
				for n := 0; n < len(ns_name); n++ {
					if (low_ip_info[n] == nil) || (low_ip_info[n].srtt >= info.srtt) {
						for m := len(ns_name) - 1; m > n; m-- {
							low_ip_info[m] = low_ip_info[m-1]
							ns_name[m] = ns_name[m-1]
						}
						low_ip_info[n] = info
						ns_name[n] = ns.name
						break
					}
				}
			}
		}
		for p := 0; (p < len(ns_name)) && (low_ip_info[p] != nil); p++ {
			targets = append(targets, &query_target{ip: low_ip_info[p].ip, ns_name: ns_name[p]})
		}
	} else {
		var all_targets []*query_target
		for _, ns := range srvs.ns {
			for _, info := range ns.ip_info {
				all_targets = append(all_targets, &query_target{ip: info.ip, ns_name: ns.name})
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

func (srvs *yeti_server_set) update_srtt(ip net.IP, rtt time.Duration) {
	glog.V(3).Infof("update_srtt ip=%s, rtt=%s", ip, rtt)
	srvs.lock.Lock()
	defer srvs.lock.Unlock()

	for _, ns_info := range srvs.ns {
		for _, ip_info := range ns_info.ip_info {
			// update the time for the IP that we just queried
			if ip_info.ip.Equal(ip) {
				if ip_info.srtt == 0 {
					ip_info.srtt = rtt
				} else {
					ip_info.srtt = ((ip_info.srtt * 7) + (rtt * 3)) / 10
				}
				glog.V(2).Infof("%s: update SRTT ip=%s, srtt=%s", ns_info.name, ip_info.ip, ip_info.srtt)
				// all other IP have their time decayed a bit
			} else {
				// There may be overflow issues to worry about here. Durations
				// are 64-bit nanoseconds, so we should be able to handle any
				//
				ip_info.srtt = (ip_info.srtt * 49) / 50
				glog.V(3).Infof("%s: decay SRTT ip=%s, srtt=%s", ns_info.name, ip_info.ip, ip_info.srtt)
			}
		}
	}
}
