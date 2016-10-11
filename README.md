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

You need the Go language packet library from Google:

    $ go get github.com/google/gopacket

You need the glog logging library from Google:

    $ go get github.com/golang/glog

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
      -alsologtostderr
            log to standard error as well as files
      -c    use non-obfuscated (clear) query names
      -d string
            base file name to store difference details in (default none)
      -e uint
            set EDNS0 buffer size (set to 0 to use original query size) (default 4093)
      -log_backtrace_at value
            when logging hits line file:N, emit a stack trace
      -log_dir string
            If non-empty, write log files in this directory
      -logtostderr
            log to standard error instead of files
      -p string
            base file name to store performance comparison in (default none)
      -s string
            secret for obfuscated query names, hex-encoded (default random-generated)
      -stderrthreshold value
            logs at or above this threshold go to stderr
      -v value
            log level for V logs
      -vmodule value
            comma-separated list of pattern=N settings for file-filtered logging

### Comparing Query Times

The `ymmv` program can be used to compare performance between IANA
root servers and Yeti root servers.

Using the `-p` flag tells the program to log each query times to a
file. The file name contains the date added to the name. So if we used
`-p ymmv-perf` for the flag, we would get files like:

    ymmv-perf.2016-10-09.log
    ymmv-perf.2016-10-10.log
    ymmv-perf.2016-10-11.log

The contents of each file look something like this:

```
#              time, iana_rtt, yeti_rtt,            iana_root,                           yeti_root,       qtype, qname
2016-10-11T00:31:23, 0.022854, 0.192096,          199.7.83.42,                2001:e30:1c1e:1::333,           A, wlan1.
2016-10-11T00:32:55, 0.001481, 0.009405,          192.5.5.241,              2a02:990:100:b01::53:0,           A, be.
2016-10-11T00:32:57, 0.110079, 0.255293,         192.112.36.4,                  2001:e30:187d::333,           A, be.
2016-10-11T00:32:58, 0.001709, 0.011197,        192.58.128.30,            2001:1608:10:167:32e::53,           A, me.
2016-10-11T00:32:58, 0.001919, 0.015572,        192.36.148.17,            2001:1608:10:167:32e::53,           A, us.
2016-10-11T00:32:58, 0.085999, 0.011112,        198.97.190.53,                  2001:67c:217c:6::2,           A, us.
2016-10-11T00:32:58, 0.206600, 0.010914,       192.203.230.10,                  2001:67c:217c:6::2,           A, me.
2016-10-11T00:33:02, 0.080698, 0.023102,          199.7.91.13, 2001:4b98:dc2:45:216:3eff:fe4b:8c5b,           A, ch.
```

The file contains comma-separated values (CSV), one per line. You see
the time the query was made, the time it took for the IANA root server
to reply, the time it took the Yeti root server to reply, and finally
the query type and name.

### Recording Differences

The `ymmv` program can record the differences in the answers that
the IANA root servers and the Yeti root servers give.

Using the `-d` flag tells the program to log each query times to a
file. The file name contains the date added to the name. So if we used
`-d ymmv-diff` for the flag, we would get files like:

    ymmv-diff.2016-10-09.log
    ymmv-diff.2016-10-10.log
    ymmv-diff.2016-10-11.log

The contents of each file look something like this:

```
================================================================================
2016-10-11T10:06:17
qname: example.net
qtype: A
IANA IP: 199.7.83.42
Yeti IP: 2001:e30:1c1e:1::333
----------------------------------------
SOA only for Yeti:  . 86400 IN SOA www.yeti-dns.org. hostmaster.yeti-dns.org. 2016101100 1800 900 604800 86400
```

The '====' line starts each set of differences, and is followed by
information about the query. The '----' line starts the section of
differences, which are one per line. There may be any number of
differences discovered in a single query.

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

### Logging Details

The following flags control details about the logging output:

      -alsologtostderr
            log to standard error as well as files
      -log_backtrace_at value
            when logging hits line file:N, emit a stack trace
      -log_dir string
            If non-empty, write log files in this directory
      -logtostderr
            log to standard error instead of files
      -stderrthreshold value
            logs at or above this threshold go to stderr
      -v value
            log level for V logs
      -vmodule value
            comma-separated list of pattern=N settings for file-filtered logging

These are all added by the Go `glog` package, and most have the
expected usage. The `-v` flag may be confusing, as the normal practice
of adding just `-v` or multiple `-v` is not supported.  Instead you
specify the debugging logging level, like `-v 1` or `-v 2`. Higher
numbers mean more logging output.

By default log files are placed in `/tmp` and are named something like
`ymmv.${hostname}.${login}.log.INFO.${date_time}.${pid}` and
`ymmv.${hostname}.${login}.log.WARNING.${date_time}.${pid}`. A
symbolic link is made from `ymmv.INFO` and `ymmv.WARNING` to the
latest version.

Limitations
===========
There are several limitations right now, being worked on:

* IP fragments are not handled by the pcap parser.
* TCP streams are not reassembled by the pcap parser.

The [PcapParser](https://github.com/RunxiaWan/PcapParser) can be used
to perform IP fragment reassembly and extract DNS queries and answers
from TCP streams. It will be further integrated in the future.

* No easy way exists to report differences found back to the Yeti
  operators. This will be added as an opt-in "--email-to" command-line
  option.
