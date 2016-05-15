#! /bin/sh

if [ $# -ne 1 ]; then
  echo "Syntax: $0 interface" >&2
  exit 1
fi

# make a temporary directory
WORK_DIR=`mktemp -d`

function cleanup {
  rm -rf "$WORK_DIR"
}

trap cleanup EXIT

# make a FIFO (named pipe) to push pcap data down
mkfifo $WORK_DIR/pipe

# start capturing data in a background process
(
  while true; do
    tcpdump -i $1 -s0 -w $WORK_DIR/pipe -U port 53
  done
) &

CAPTURE_PID=$!

function shutdown_capture {
  rm -rf "$WORK_DIR"
  kill $CAPTURE_PID
}

trap shutdown_capture EXIT

# now just hang out
while true; do
  ./pcap2ymmv $WORK_DIR/pipe >> ymmv.dat
done
