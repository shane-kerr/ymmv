package dnsstub

import (
	"crypto/rand"
	"fmt"
	"github.com/miekg/dns"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"
)

type query struct {
	handle int // identifier to match answer with question
	qname  string
	rtype  uint16
}

type answer struct {
	handle int // identifier to match answer with question
	qname  string
	rtype  uint16
	answer *dns.Msg
	rtt    time.Duration
	err    error
}

type StubResolver struct {
	lock             sync.Mutex
	cond             *sync.Cond
	next_handle      int
	queries          chan *query
	finished_answers []*answer
}

func RandUint16() (uint16, error) {
	var id_max big.Int
	id_max.SetUint64(65536)
	id, err := rand.Int(rand.Reader, &id_max)
	if err != nil {
		return 0, err
	}
	return uint16(id.Uint64()), nil
}

/*
   Send a query to a DNS server, retrying and handling truncation.
*/
func DnsQuery(server string, query *dns.Msg) (*dns.Msg, time.Duration, error) {
	// try to query first in UDP
	dnsClient := new(dns.Client)
	id, err := RandUint16()
	if err != nil {
		return nil, 0, err
	}
	query.Id = id
	var r *dns.Msg
	var rtt time.Duration
	// try a few times with UDP
	for i := 0; i < 3; i++ {
		r, rtt, err = dnsClient.Exchange(query, server)
		if err != nil {
			// no need to retry if we get a truncated answer
			if err == dns.ErrTruncated {
				break
			}
			// if we have a non-timeout error return it
			nerr, ok := err.(net.Error)
			if !(ok && nerr.Timeout()) {
				return nil, 0, err
			}
		}
		if (r != nil) && (r.Rcode == dns.RcodeSuccess) {
			if r.Truncated {
				break
			}
			return r, rtt, nil
		}
	}
	// if we got a truncation or timeouts, try again in TCP
	dnsClient.Net = "tcp"
	r, rtt, err = dnsClient.Exchange(query, server)
	if err != nil {
		return nil, 0, err
	}
	// return whatever we get in this case, even if an erroneous response
	return r, rtt, nil
}

func stub_resolve(resolver *StubResolver, servers []string) {
	for q := range resolver.queries {
		dns_query := new(dns.Msg)
		dns_query.RecursionDesired = true
		dns_query.SetQuestion(q.qname, q.rtype)
		a := new(answer)
		a.handle = q.handle
		a.qname = q.qname
		a.rtype = q.rtype
		a.answer = nil
		for _, server := range servers {
			// look for ':' because that indicates an IPv6 address
			var resolver string
			if strings.ContainsRune(server, ':') {
				resolver = "[" + server + "]:53"
			} else {
				resolver = server + ":53"
			}
			a.answer, a.rtt, a.err = DnsQuery(resolver, dns_query)
			if a.answer != nil {
				break
			}
		}
		resolver.lock.Lock()
		resolver.finished_answers = append(resolver.finished_answers, a)
		resolver.cond.Broadcast()
		resolver.lock.Unlock()
	}
}

func Init(concurrency int, server_ips []net.IP) (resolver *StubResolver, err error) {
	stub := new(StubResolver)
	var servers []string
	for _, ip := range server_ips {
		servers = append(servers, ip.String())
	}
	if len(servers) == 0 {
		resolv_conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			newerr := fmt.Errorf("error reading resolver configuration from '/etc/resolv.conf'; %s", err)
			return nil, newerr
		}
		servers = resolv_conf.Servers
	}
	stub.queries = make(chan *query, concurrency*4)
	for i := 0; i < concurrency; i++ {
		go stub_resolve(stub, servers)
	}
	stub.cond = sync.NewCond(&stub.lock)
	return stub, nil
}

func (resolver *StubResolver) AsyncQuery(qname string, rtype uint16) (handle int) {
	q := new(query)
	resolver.lock.Lock()
	resolver.next_handle += 1
	q.handle = resolver.next_handle
	resolver.lock.Unlock()
	q.qname = qname
	q.rtype = rtype
	resolver.queries <- q
	return q.handle
}

func (resolver *StubResolver) Wait() (*dns.Msg, time.Duration, string, uint16, error) {
	resolver.lock.Lock()
	defer resolver.lock.Unlock()

	for len(resolver.finished_answers) == 0 {
		resolver.cond.Wait()
	}

	a := resolver.finished_answers[0]
	resolver.finished_answers = resolver.finished_answers[1:]
	return a.answer, a.rtt, a.qname, a.rtype, a.err
}

// Wait for a specific handle.
// Note that mixing Wait() and WaitByHandle() is dangerous because
// a Wait() may read a result before the WaitByHandle() gets it, so
// it may wait forever.
func (resolver *StubResolver) WaitByHandle(handle int) (*dns.Msg, time.Duration, string, uint16, error) {

	resolver.lock.Lock()
	defer resolver.lock.Unlock()

	for {
		for n, a := range resolver.finished_answers {
			if a.handle == handle {
				resolver.finished_answers = append(resolver.finished_answers[:n],
					resolver.finished_answers[n+1:]...)
				return a.answer, a.rtt, a.qname, a.rtype, a.err
			}
		}
		resolver.cond.Wait()
	}
}

func (resolver *StubResolver) SyncQuery(qname string, rtype uint16) (*dns.Msg, time.Duration, error) {
	handle := resolver.AsyncQuery(qname, rtype)
	answer, rtt, _, _, err := resolver.WaitByHandle(handle)
	return answer, rtt, err
}

func (resolver *StubResolver) Close() {
	close(resolver.queries)
}
