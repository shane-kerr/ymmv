package dnsstub

import (
	"fmt"
	"github.com/miekg/dns"
	"io"
	"net"
	"strings"
	"testing"
)

func TestRandUint16(t *testing.T) {
	_, err := RandUint16()
	if err != nil {
		t.Errorf("Error getting a random number: %s", err)
	}
}

type NetworkAddr struct {
	Network string
	Addr string
}

type DnsMessageRead struct {
	Message *dns.Msg
	UdpInfo *net.UDPConn
	SrcAddr net.Addr
	TcpInfo *net.TCPConn
	Error error
}

type DnsServer struct {
	Addrs []NetworkAddr
	TCPListeners []*net.TCPListener
	UDPConns []*net.UDPConn
	MsgReader chan *DnsMessageRead
}

func DnsMessageReadUDP(conn *net.UDPConn, msg_chan chan<- *DnsMessageRead) {
	for {
		var result DnsMessageRead
		buffer := make([]byte, 65536, 65536)
		_, src, err := conn.ReadFrom(buffer)
		if err != nil {
			result.Message = nil
			result.UdpInfo = nil
			result.SrcAddr = nil
			result.TcpInfo = nil
			result.Error = err
			msg_chan <- &result
			return
		}
		var dns_msg dns.Msg
		err = dns_msg.Unpack(buffer)
		if err != nil {
			result.Message = nil
			result.UdpInfo = nil
			result.SrcAddr = nil
			result.TcpInfo = nil
			result.Error = err
			msg_chan <- &result
			return
		} else {
			result.Message = &dns_msg
			result.UdpInfo = conn
			result.SrcAddr = src
			result.TcpInfo = nil
			result.Error = nil
			msg_chan <- &result
		}
	}
}

func DnsMessageReadTCP(conn *net.TCPConn, msg_chan chan<- *DnsMessageRead) {
	for {
		var result DnsMessageRead
		msglenbuf := make([]byte, 2, 2)
		_, err := io.ReadFull(conn, msglenbuf)
		if err != nil {
			result.Message = nil
			result.UdpInfo = nil
			result.SrcAddr = conn.RemoteAddr()
			result.TcpInfo = conn
			result.Error = err
			msg_chan <- &result
			return
		}
		msglen := (msglenbuf[0] << 8) | msglenbuf[1]
		buffer := make([]byte, msglen, msglen)
		_, err = io.ReadFull(conn, buffer)
		if err != nil {
			result.Message = nil
			result.UdpInfo = nil
			result.SrcAddr = conn.RemoteAddr()
			result.TcpInfo = conn
			result.Error = err
			msg_chan <- &result
			return
		}
		var dns_msg dns.Msg
		err = dns_msg.Unpack(buffer)
		if err != nil {
			result.Message = nil
			result.UdpInfo = nil
			result.SrcAddr = conn.RemoteAddr()
			result.TcpInfo = conn
			result.Error = err
			msg_chan <- &result
			return
		} else {
			result.Message = &dns_msg
			result.UdpInfo = nil
			result.SrcAddr = conn.RemoteAddr()
			result.TcpInfo = conn
			result.Error = nil
			msg_chan <- &result
		}
	}
}

func DnsMessageListenTCP(listener *net.TCPListener, msg_chan chan<- *DnsMessageRead) {
	conns := make([]*net.TCPConn, 0, 0)
	for {
		// get next TCP connection
		conn, err := listener.AcceptTCP()
		if err != nil {
			// close up shop
			for _, conn := range(conns) {
				conn.Close()
			}
			break
		}
		// Note that we don't ever collect connections until we quit.
		// This would be a problem in a real DNS server, but for our
		// test setup we don't care.
		conns = append(conns, conn)
		// start our reader goroutine
		go DnsMessageReadTCP(conn, msg_chan)
	}
}

// Note that we don't clean up bound addresses on error, because this is
// for the test server. If this code was adapted for use in production
// then these listeners would have to be closed on error.
func InitDnsServer(hostports []string) (*DnsServer, error) {
	addrs := make([]NetworkAddr, 0, 0)
	tcp_listeners := make([]*net.TCPListener, 0, 0)
	udp_conns := make([]*net.UDPConn, 0, 0)
	msg_chan := make(chan *DnsMessageRead, len(hostports) * 4)
	for _, hostport := range(hostports) {
		// if no port is specified, default to port 53
		if !strings.ContainsRune(hostport, ':') {
			hostport = hostport + ":53"
		}
		// set up our UDP listener
		udp_addr, err := net.ResolveUDPAddr("udp", hostport)
		if err != nil {
			return nil, err
		}
		udp_conn, err := net.ListenUDP("udp", udp_addr)
		if err != nil {
			return nil, err
		}
		udp_conns = append(udp_conns, udp_conn)
		new_hostport := udp_conn.LocalAddr().String()
		addrs = append(addrs, NetworkAddr{"udp", new_hostport})
		// start the UDP reader goroutine
		go DnsMessageReadUDP(udp_conn, msg_chan)
		// set up our TCP listener
		tcp_addr, err := net.ResolveTCPAddr("tcp", new_hostport)
		if err != nil {
			return nil, err
		}
		tcp_listener, err := net.ListenTCP("tcp", tcp_addr)
		if err != nil {
			return nil, err
		}
		tcp_listeners = append(tcp_listeners, tcp_listener)
		addrs = append(addrs, NetworkAddr{"tcp", tcp_listener.Addr().String()})
		// start the TCP reader goroutine
		go DnsMessageListenTCP(tcp_listener, msg_chan)
	}
	var server DnsServer
	server.Addrs = addrs
	server.TCPListeners = tcp_listeners
	server.UDPConns = udp_conns
	server.MsgReader = msg_chan
	return &server, nil
}

func (srv *DnsServer) Answer(answers []*dns.Msg) {
	for _, answer := range(answers) {
		fmt.Printf("%s\n", answer)
		msg_read := <-srv.MsgReader
		if msg_read.Error != nil {
			fmt.Printf("Error reading DNS message: %s", msg_read.Error)
			return
		}
		query := msg_read.Message
		answer.Id = query.Id
		buffer, err := answer.Pack()
		if err != nil {
			fmt.Printf("Error packing DNS answer: %s", err)
			return
		}
		if msg_read.UdpInfo != nil {
			_, err = msg_read.UdpInfo.WriteTo(buffer, msg_read.SrcAddr)
			if err != nil {
				fmt.Printf("Error writing DNS answer via UDP: %s", err)
				return
			}
		}
	}
}

func SetupDnsServer() (server *DnsServer, err error) {
	server = nil
	for n := 0; (server == nil) && (n < 10); n++ {
		server, err = InitDnsServer([]string{"[::1]:0",})
		if server != nil {
			break
		}
		// TODO: check for "port already in use"
	}
	return server, err
}


func TestDnsQuery(t *testing.T) {
	server, err := InitDnsServer([]string{"[::1]:0",})
	if err != nil {
		t.Fatalf("Error initializing DNS server: %s", err)
	}
	fmt.Printf("%s\n", server.Addrs)
	var msg dns.Msg
	msg.SetQuestion("hostname.bind.", dns.TypeTXT)
	msg.Question[0].Qclass = dns.ClassCHAOS
	server.Answer([]*dns.Msg{&msg,})
/*
	var msg dns.Msg
	msg.SetQuestion("hostname.bind", dns.TypeTXT)
	msg.Question[0].Qclass = dns.ClassCHAOS
	var info server_info
	server := dns.Server{Addr: "[::1]:0", Net: "udp", Handler: &info}
	go server.ListenAndServe()
	// busy-loop waiting for server to start
	server.lock.Lock()
	for !server.started {
		server.lock.Unlock()
		server.lock.Lock()
	}
//	defer server.lock.Unlock()
//	port := server.Listener
//	DnsQuery("::1", 
	server.Shutdown()
	*/
}

