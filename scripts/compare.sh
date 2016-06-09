#! /bin/sh

# This script listens for answer packets from the IANA root servers on
# the interface given. The questions are sent to the Yeti root servers
# and the answers compared. If the Yeti answer is different from the
# IANA answer, the differences are logged.
#
# There are three programs run, and packets are passed between them:
#
# 1. tcpdump captures answer packets on the interface
#
# 2. pcap2ymmv reads these packets, finds those from an IANA root
#    server, and then generates a query:answer pair in ymmv format
#
# 3. ymmv reads the query:answer pairs and then sends a query to one
#    or more Yeti servers
#
# Notes:
#
# * Any program that produces pcap output can be used as input instead
#   of tcpdump.
#
# * The user running the program needs to have permission to capture
#   packets. For tcpdump this is usually the root user, for tshark
#   this is usually users in the "wireshark" group.
#
# 2016-06-09
# shane@biigroup.cn

# executables
YMMV_DIR=..
PCAP2YMMV=${YMMV_DIR}/pcap2ymmv/pcap2ymmv
YMMV=${YMMV_DIR}/ymmv/ymmv

# if we are called without an argument, output a usage message
if [ $# -ne 1 ]; then
  echo "Syntax: $0 interface" >&2
  exit 1
fi

# packet capture program
DUMP="tcpdump -i $1 -w- -U -q udp port 53"
#DUMP="tshark -i $1 -F pcap -w - -l -q port 53"

$DUMP | $PCAP2YMMV | $YMMV
