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
servers, a version will be sent to the some Yeti root servers.
Initially the particular Yeti server will be round-robin from a list
of servers (or the whole set if none is specified), but later we will
add RTT-based server selection.

The Yeti answer that is returned will be compared to the IANA answer,
and if there is a difference this will be logged. Administrators will
have to ability to opt-in to having their logs periodically e-mailed
to the Yeti project.


Installation
============
You need the `libpcap` library, which can be downloaded from the
[tcpdump](http://www.tcpdump.org/) project page. On a Debian or
Debian-derived systems installation will look something like this:

    $ sudo apt install libpcap-dev

You need the Go language `pcap` and `dns` libraries from the awesome
Miek Gieben:

    $ go get github.com/miekg/pcap
    $ go get github.com/miekg/dns

To build the `pcap` to `ymmv` filter/converter:

    $ cd pcap2ymmv
    $ go build

To build the `ymmv` program itself:

   $ cd ymmv
   $ go build

Running
=======
A shell script which writes `tcpdump` output to a file is in the
`pcap2ymmv` directory, and can be used like this:

   $ sudo sh capture.sh eth0

For now this will create `ymmv.dat`, although the expectation is that
this will be able to be used as input for the `ymmv` program later,
like this:

   $ sudo sh capture.sh eth0 | ymmv --mail-logs


Limitations
===========
There are lots of limitations right now, being worked on:

* The ymmv program itself is still being developed. It does not work.
* IP fragments are not handled by the pcap parser.
* TCP streams are not reassembled by the pcap parser.

We are currently working on finishing the ymmv program and
reassembling IP fragments. We will log TCP to see if it is actually
used much, and if so we will try to build a solution for that.

