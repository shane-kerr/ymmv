This file describes the data format used as input for the ymmv
program.

The file is a binary file, with numbers stored in most-significant
byte ordering (also known as 'network byte ordering').

The input stream consists of a series of queries and answers, with one
answer per query.

Each query/answer pair starts with a magic value. Since some of the
information is variable-length, programs (or people) can use this to
ensure that they do not get out of sync while processing a stream.

The contents of each query/answer pair are:

* 32-bit magic value: "ymmv", a constant that we check to make sure
  nothing goes wrong in our stream

* '4' or '6' depending on IP address family (IPv4 or IPv6)

* 't' or 'u' depending on protocol (TCP or UDP)

* 32-bit or 128-bit IP address of server

* 32-bit Unix epoch of query
 
* 32-bit nanoseconds of query

* 16-bit length of DNS query

* DNS message raw bytes

* 32-bit Unix epoch of query

* 32-bit nanoseconds of query

* 16-bit length of DNS answer

* DNS answer raw bytes
