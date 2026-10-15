package sockets

import (
	"reflect"
	"testing"
)

const tcpFixture = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:AC67 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 20066 2 00000000013a4f8a 100 0 0 10 0
   1: 00000000:2810 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 27899 2 00000000d79e3202 100 0 0 10 0
   2: 020012AC:9C40 020012AC:192B 01 00000000:00000000 02:000AF7BF 00000000     0        0 31337 2 0000000025aa5f5c 20 4 30 10 -1
`

const udpFixture = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  734: 0B00007F:B8C0 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 16073 2 000000009584953d 0
  735: 020012AC:D2F0 08080808:0035 01 00000000:00000000 00:00000000 00000000     0        0 16074 2 000000009584953d 0
`

const tcp6Fixture = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 40001 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0CEA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 40002 1 0000000000000000 100 0 0 10 0
   2: 0000000000000000FFFF00000100007F:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 40003 1 0000000000000000 100 0 0 10 0
   3: B80D0120000000000000000001000000:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 40004 1 0000000000000000 100 0 0 10 0
`

func TestParseProcNet(t *testing.T) {
	tests := []struct {
		proto, data string
		want        []netEntry
	}{
		{"tcp", tcpFixture, []netEntry{
			{Proto: "tcp", Local: "127.0.0.1:44135", Peer: "0.0.0.0:*", State: "LISTEN", Inode: 20066},
			{Proto: "tcp", Local: "0.0.0.0:10256", Peer: "0.0.0.0:*", State: "LISTEN", Inode: 27899},
		}},
		{"udp", udpFixture, []netEntry{
			{Proto: "udp", Local: "127.0.0.11:47296", Peer: "0.0.0.0:*", State: "UNCONN", Inode: 16073},
		}},
		{"tcp6", tcp6Fixture, []netEntry{
			{Proto: "tcp6", Local: "[::]:443", Peer: "[::]:*", State: "LISTEN", Inode: 40001},
			{Proto: "tcp6", Local: "[::1]:3306", Peer: "[::]:*", State: "LISTEN", Inode: 40002},
			{Proto: "tcp6", Local: "[::ffff:127.0.0.1]:8080", Peer: "[::]:*", State: "LISTEN", Inode: 40003},
			{Proto: "tcp6", Local: "[2001:db8::1]:80", Peer: "[::]:*", State: "LISTEN", Inode: 40004},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.proto, func(t *testing.T) {
			got, err := parseProcNet(tt.proto, []byte(tt.data))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got  %+v\nwant %+v", got, tt.want)
			}
		})
	}
}

func TestParseProcNetRejectsGarbage(t *testing.T) {
	for _, data := range []string{
		"header\n 0: ZZ00007F:AC67 00000000:0000 0A 0 0 0 0 0 20066\n",
		"header\n 0: 0100007F:AC67 00000000:0000 0A 0 0 0 0 0 notanumber\n",
		"header\n 0: 0100007F\n",
	} {
		if _, err := parseProcNet("tcp", []byte(data)); err == nil {
			t.Errorf("expected error for %q", data)
		}
	}
}
