package authz

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/internal/xds/rbac"
)

var (
	dlog = logrus.WithField("interzeptor", "authz")

	refreshPolicyDuration = time.Minute
	authzPolicyFile       = "/security/authz/policy.json"
)

// FileWatcherInterceptor contains details used to make authorization decisions
// by watching a file path that contains authorization policy in JSON format.
type FileWatcherInterceptor struct {
	engines         rbac.ChainEngine
	policyFile      string
	policyContents  []byte
	refreshDuration time.Duration
	cancel          context.CancelFunc
}

// NewFileWatcher returns a new FileWatcherInterceptor from a policy file
// that contains JSON string of authorization policy and a refresh duration to
// specify the amount of time between policy refreshes.
func NewFileWatcher() (*FileWatcherInterceptor, error) {
	if authzPolicyFile == "" {
		return nil, fmt.Errorf("authorization policy file path is empty")
	}
	if refreshPolicyDuration <= time.Duration(0) {
		return nil, fmt.Errorf("requires refresh interval(%v) greater than 0s", refreshPolicyDuration)
	}
	i := &FileWatcherInterceptor{policyFile: authzPolicyFile, refreshDuration: refreshPolicyDuration}
	if err := i.updateInternalInterceptor(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	i.cancel = cancel
	// Create a background go routine for policy refresh.
	go i.run(ctx)
	return i, nil
}

// NewStatic returns a new StaticInterceptor from a static authorization policy
// JSON string.
func (f *FileWatcherInterceptor) initEngine(authzPolicy string) error {
	rbacs, policyName, err := translatePolicy(authzPolicy)
	if err != nil {
		return err
	}
	chainEngine, err := rbac.NewChainEngine(rbacs, policyName)
	if err != nil {
		return err
	}

	f.engines = *chainEngine
	return nil
}

func (f *FileWatcherInterceptor) run(ctx context.Context) {
	ticker := time.NewTicker(f.refreshDuration)
	for {
		if err := f.updateInternalInterceptor(); err != nil {
			dlog.Warningf("authorization policy reload status err: %v", err)
		}
		select {
		case <-ctx.Done():
			ticker.Stop()
			return
		case <-ticker.C:
		}
	}
}

// updateInternalInterceptor checks if the policy file that is watching has changed,
// and if so, updates the internalInterceptor with the policy. Unlike the
// constructor, if there is an error in reading the file or parsing the policy, the
// previous internalInterceptors will not be replaced.
func (f *FileWatcherInterceptor) updateInternalInterceptor() error {
	policyContents, err := os.ReadFile(f.policyFile)
	if err != nil {
		return fmt.Errorf("policyFile(%s) read failed: %v", f.policyFile, err)
	}
	if bytes.Equal(f.policyContents, policyContents) {
		return nil
	}
	f.policyContents = policyContents
	policyContentsString := string(policyContents)
	return f.initEngine(policyContentsString)
}

// Authorize determines if the incoming RPC is authorized by the current policy.
func (f *FileWatcherInterceptor) Authorize(ctx context.Context) error {
	return f.engines.IsAuthorized(ctx)
}
