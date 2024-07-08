package acctz

import (
	"context"
	"net"
	"net/url"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	apb "github.com/openconfig/gnsi/acctz"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestRecordFromContext(t *testing.T) {
	sid, err := url.Parse("spiffeid://me")
	if err != nil {
		t.Fatalf("unable to parse spiffe id: %v", err)
	}
	tests := []struct {
		name       string
		inPeer     *peer.Peer
		wantRecord *apb.RecordResponse
		wantError  bool
	}{
		{
			name:      "no-peer",
			wantError: true,
		},
		{
			name:   "empty-peer",
			inPeer: &peer.Peer{},
			wantRecord: &apb.RecordResponse{
				ComponentName: os.Args[0],
				SessionInfo: &apb.SessionInfo{
					LocalAddress:  "unknown-host",
					LocalPort:     0,
					RemoteAddress: "unknown-host",
					RemotePort:    0,
					Status:        apb.SessionInfo_SESSION_STATUS_OPERATION,
					User: &apb.UserDetail{
						Identity: "unknown-user",
					},
				},
			},
		},
		{
			name: "good-peer",
			inPeer: &peer.Peer{
				Addr: &net.TCPAddr{
					IP:   net.IPv4(192, 0, 0, 2),
					Port: 1,
				},
				LocalAddr: &net.TCPAddr{
					IP:   net.IPv4(192, 0, 0, 1),
					Port: 1,
				},
				AuthInfo: credentials.TLSInfo{
					SPIFFEID: sid,
				},
			},
			wantRecord: &apb.RecordResponse{
				ComponentName: os.Args[0],
				SessionInfo: &apb.SessionInfo{
					LocalAddress:  "192.0.0.1",
					LocalPort:     1,
					RemoteAddress: "192.0.0.2",
					RemotePort:    1,
					IpProto:       6,
					Status:        apb.SessionInfo_SESSION_STATUS_OPERATION,
					User: &apb.UserDetail{
						Identity: "spiffeid://me",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := New()
			ctx := peer.NewContext(context.Background(), test.inPeer)
			got, err := recorder.RecordFromContext(ctx)
			if test.wantError != (err != nil) {
				t.Errorf("RecordFromContext returned incorrect error state. wantError: %t, got error: %t", test.wantError, err != nil)
			}

			if diff := cmp.Diff(test.wantRecord, got, protocmp.Transform(), protocmp.IgnoreFields(&apb.RecordResponse{}, "timestamp")); diff != "" {
				t.Errorf("RecordFromContext returned diff (-want, +got):\n%s", diff)
			}
		})
	}
}
