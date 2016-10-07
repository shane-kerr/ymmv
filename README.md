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
servers, a version is be sent to the some Yeti root servers. By
default the Yeti server is chosen using a smoothed round-trip time
(SRTT) algorithm, modeled after the BIND 9 algorithm, but other
options such as round-robin or random are also possible.

The Yeti answer that is returned is compared to the IANA answer, and
if there is a difference this is logged. Later, administrators will
have to ability to opt-in to having their logs periodically e-mailed
to the Yeti project.


Installation
============
The software is written in the Go language, with some optional Bourne
shell scripts.

To build the binaries yourself, you need to have Go installed.

You can download the source code from GitHub: 
 
https://github.com/shane-kerr/ymmv/archive/master.zip

You can also use git to clone the repository:

    $ git clone https://github.com/shane-kerr/ymmv.git

You need the `libpcap` library, which can be downloaded from the
[tcpdump](http://www.tcpdump.org/) project page. On a Debian or
Debian-derived system installation will look something like this:

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

The binaries are statically linked, so you can just copy them to any
system that you want to run them on.

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


ymmv Command-Line
=================
Whether you customize `compare.sh` or use some other means to run
`ymmv`, you have some command-line options available.

You can see these options via `ymmv -h`:

    Usage of ./ymmv:
      -a string
            set server-selection algorithm, either rtt, round-robin, random, or all (default "rtt")
      -c    use non-obfuscated (clear) query names
      -e uint
            set EDNS0 buffer size (set to 0 to use original query size) (default 4093)
      -s string
            secret for obfuscated query names, hex-encoded (default random-generated)

### Server Selection Algorithm

The ymmv program will choose one of the Yeti root servers to send
queries to, based on the server selection algorithm.

* **rtt**: The default algorithm is "rtt", which uses a smoothed
  round-trip time (SRTT) to pick which server to use. This is based
  off of the BIND 9 algorithm, where it prefers the fastest server,
  but will periodically try other servers so that if the network or
  server performance changes and those become faster that those are
  used. This mimics the behavior of real resolvers the most closely.

* **round-robin**: This algorithm cycles through all of the servers,
  in-order. It is useful to insure that all of the Yeti servers are
  tested relatively equally.

* **random**: With "random" each time we pick a server we choose one
  at random. This also selects all of the Yeti servers approximately
  equally, but is less predictable. The randomness may help avoid some
  artifacts that may result from the "round-robin" algorithm.

* **all**: It is also possible to send each query to _all_ of the Yeti
  root servers. This will increase the load on the Yeti system, and
  provide a clear view of the performance of each Yeti server. It does
  not act like a real resolver however.

### Obfuscated Query Names

By default, `ymmv` will obfuscate the query names (QNAME) that it
sends to the Yeti root servers.

The obfuscated query is generated via a hash function so that we
consistently send the same random query for the same actual queries.
There is a secret mixed in, so that it is not possible for the
authoritative operator to use a dictionary attack to figure out the
original query.

Here we see a basic obfuscation:

    DEBUG 13:07:26.699347 obfuscated fugazi.org. to ymmv.7ffc968b471b6cb0.org.

We use the same obfuscated string for a different QTYPE. We _could_
mix the QTYPE into the hash input to avoid this property, but this is
not done now.

You can specify the obfuscation secret on startup, otherwise it will
be generated randomly. Use the `-s` flag to set this secret. This is
useful if you want consistent values across different runs on the same
machine, for example. If the secret is generated randomly, `ymmv` will
log the result when it starts, something like this:

    2016/10/04 15:02:18 using obfuscation secret 99DF398E70D5462B

To disable obfuscation completely and send the original, clear QNAME,
use the `-c` flag.

### EDNS Buffer Size

By default `ymmv` uses an unusual buffer size, 4093. This should make
it easier to spot use of `ymmv` on the authoritative side. You can use
the `-e` flag to set this to some other value. A value of 0 means to
use the EDNS buffer size of the original query.

Limitations
===========
There are several limitations right now, being worked on:

* IP fragments are not handled by the pcap parser.
* TCP streams are not reassembled by the pcap parser.

We are currently working on a separate program which will perform IP
fragment reassembly and extract DNS queries and answers from TCP
streams.

* No easy way exists to report differences found back to the Yeti
  operators. This will be added as an opt-in "--email-to" command-line
  option.

* Missing verbose flags to help debugging.
