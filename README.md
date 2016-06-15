Yeti Many Mirror Verifier
=========================

This is the `ymmv` utility. It is designed to make it easy and safe
for a DNS administrator to copy their resolver IANA root DNS traffic
to the Yeti root.

The program is designed to be able to take several styles of input.
Something like [dnstap](http://dnstap.info/) will be the best source
of input, but since
[pcap](https://wiki.wireshark.org/Development/LibpcapFileFormat)
files (produced by `tcpdump` and other programs) are very common, that
is the first input that has been implemented. The `ymmv` format can
be found in
[ymmv-format.md](https://github.com/shane-kerr/ymmv/blob/master/ymmv-format.md).

For each query and answer that the resolver has made to the IANA root
servers, a version is be sent to the some Yeti root servers. Initially
the particular Yeti server is be round-robin from a list of servers
(or all Yeti servers if none is specified), but later we will add
random, all, and RTT-based server selection.

The Yeti answer that is returned is compared to the IANA answer, and
if there is a difference this is logged. Later, administrators will
have to ability to opt-in to having their logs periodically e-mailed
to the Yeti project.


Installation
============
You need the `libpcap` library, which can be downloaded from the
[tcpdump](http://www.tcpdump.org/) project page. On a Debian or
Debian-derived systems installation will look something like this:

    $ sudo apt install libpcap-dev

You need the Go language `dns` library from the awesome Miek Gieben:

    $ go get github.com/miekg/dns

You also need the Go language packet library from Google:

    $ go get github.com/google/gopacket

To build the `pcap` to `ymmv` filter/converter:

    $ cd pcap2ymmv
    $ go build

To build the `ymmv` program itself:

    $ cd ymmv
    $ go build


Running
=======

The simplest way is with the `compare.sh` script. This requires
`tcpdump` on the system (although this can be changed easily to
`tshark` if preferred). A sample invocation looks like this:

    $ sudo sh scripts/compare.sh eth0

This will compare all answers from the IANA root servers with answers
to the same queries from the Yeti root servers. Differences are
displayed on the terminal.


Customization
=============
You can specify only a specific set of Yeti root servers by passing
them on the command line. For example, to replay queries and send them
only to the TISF server you could use:

    $ ymmv 2001:559:8000::6 < file.ymmv

You can use an set of servers. For example, to compare with the IANA A
and J servers, you could use:

    $ ymmv 198.41.0.4 2001:503:ba3e::2:30 192.58.128.30 2001:503:c27::2:30

Likewise, if you are using the `pcap2ymmv` program, you can specify
which servers to mirror traffic from by specifying them on the command
line. So if you only wanted the IANA F root server answers, you could
use:

    $ pcap2ymmv 192.5.5.241 2001:500:2f::f < infile.pcap > outfile.ymmv

The easiest approach is probably to update the `compare.sh` script to
suit your needs. It is fairly short and hopefully easy to modify.


Limitations
===========
There are several limitations right now, being worked on:

* IP fragments are not handled by the pcap parser.
* TCP streams are not reassembled by the pcap parser.

We are currently working on a separate program which will perform IP
fragment reassembly and extract DNS queries and answers from TCP
streams.

* No SRTT algorithm for selecting Yeti root servers to query yet
  exists. This would be helpful for making the program look more like
  a real recursive resolver.

* The Yeti servers are only looked up on start. Periodic priming will
  be added.

* The program sends the same queries to the Yeti root servers that go
  to the IANA root servers. We are working on a change to allow QNAME
  minimization on Yeti queries, which will remove personally
  identifiable information and make the tool even more widely useful.

* No easy way exists to report differences found back to the Yeti
  operators. This will be added as an opt-in "--email-to" command-line
  option.

* Missing verbose flags to help debugging.
