// Package acctz provides interceptors for gNSI.Acctz.
package acctz

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	apb "github.com/openconfig/gnsi/acctz"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	tpb "google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// bufferedRecords is the number of records to buffer before we start blocking RPC calls.
	bufferedRecords = 100
)

var (
	dlog = logrus.WithField("interzeptor", "acctz")

	// recordWindow is the time window for which we keep records.
	recordWindow = 10 * time.Minute
)

// Recorder records gNSI.Acctz records.
type Recorder struct {
	recordCh chan *apb.RecordResponse
	outputCh chan *apb.RecordResponse

	recordMu sync.Mutex
	records  []*apb.RecordResponse
}

// New returns a new Recorder.
func New() *Recorder {
	return &Recorder{
		recordCh: make(chan *apb.RecordResponse, bufferedRecords),
	}
}

// Account records a new acctz.RecordResponse such that it can be reported later.
func (r *Recorder) Account(record *apb.RecordResponse) {
	r.recordCh <- record
}

func (r *Recorder) Records() <-chan *apb.RecordResponse {
	return r.recordCh
}

// RecordFromContext constructs a record from the incoming context.
func (r *Recorder) RecordFromContext(ctx context.Context) (*apb.RecordResponse, error) {
	pi, ok := peer.FromContext(ctx)
	if !ok || pi == nil {
		return nil, fmt.Errorf("no peer information in context")
	}

	id, err := spiffeIDFromContext(pi)
	if err != nil {
		dlog.Warningf("unable to fetch spiffe id: %v", err)
	}

	spiffeID := "unknown-user"
	if id != nil {
		spiffeID = id.String()
	}

	lAddr, lPort := splitHostPort(pi.LocalAddr)
	rAddr, rPort := splitHostPort(pi.Addr)

	record := &apb.RecordResponse{
		SessionInfo: &apb.SessionInfo{
			LocalAddress:  lAddr,
			LocalPort:     lPort,
			RemoteAddress: rAddr,
			RemotePort:    rPort,
			IpProto:       ipProto(pi.LocalAddr),
			Status:        apb.SessionInfo_SESSION_STATUS_OPERATION,
			User: &apb.UserDetail{
				Identity: spiffeID,
			},
		},
		Timestamp:     tpb.Now(),
		ComponentName: os.Args[0],
	}

	return record, nil
}

func ipProto(addr net.Addr) uint32 {
	if addr == nil {
		return 0
	}

	switch addr.Network() {
	case "tcp":
		return 6
	case "udp":
		return 17
	case "ip4":
		return 4
	case "ip6":
		return 41
	case "ipv4":
		return 4
	case "ipv6":
		return 41
	}

	return 0
}

func splitHostPort(addr net.Addr) (string, uint32) {
	if addr == nil {
		return "unknown-host", 0
	}
	host, p, err := net.SplitHostPort(addr.String())
	if err != nil {
		dlog.Warningf("unable to parse address: %v", err)
		return "", 0
	}

	port, err := strconv.Atoi(p)
	if err != nil {
		dlog.Warningf("unable to parse port: %v", err)
		return "", 0
	}
	return host, uint32(port)
}

// spiffeIDFromContext checks the connection was initiated by a TLS peer and obtains the SPIFFE ID
// (https://spiffe.io/) of the peer.
func spiffeIDFromContext(p *peer.Peer) (*url.URL, error) {
	var t credentials.TLSInfo
	if p.AuthInfo != nil && p.AuthInfo.AuthType() != t.AuthType() {
		// is this even possible?
		return nil, fmt.Errorf("peer is not a TLS peer")
	}

	t, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, fmt.Errorf("peer information is not TLS")
	}

	return t.SPIFFEID, nil
}
