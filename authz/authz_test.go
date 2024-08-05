package authz

import (
	"fmt"
	"os"
	"path"
	"testing"
	"time"
)

func createTmpPolicyFile(t *testing.T, dirSuffix string, policy []byte) string {
	t.Helper()

	// Create a temp directory. Passing an empty string for the first argument
	// uses the system temp directory.
	dir, err := os.MkdirTemp("", dirSuffix)
	if err != nil {
		t.Fatalf("os.MkdirTemp() failed: %v", err)
	}
	t.Logf("Using tmpdir: %s", dir)
	// Write policy into file.
	filename := path.Join(dir, "policy.json")
	if err := os.WriteFile(filename, policy, os.ModePerm); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", filename, err)
	}
	t.Logf("Wrote policy %s to file at %s", string(policy), filename)
	return filename
}

func TestNewFileWatcher(t *testing.T) {
	tests := map[string]struct {
		authzPolicy     string
		refreshDuration time.Duration
		wantErr         error
	}{
		"InvalidRefreshDurationFailsToCreateInterceptor": {
			refreshDuration: time.Duration(0),
			wantErr:         fmt.Errorf("requires refresh interval(0s) greater than 0s"),
		},
		"InvalidPolicyFailsToCreateInterceptor": {
			authzPolicy:     `{}`,
			refreshDuration: time.Duration(1),
			wantErr:         fmt.Errorf(`"name" is not present`),
		},
		"ValidPolicyCreatesInterceptor": {
			authzPolicy: `{
				"name": "authz",
				"allow_rules":
				[
					{
						"name": "allow_all"
					}
				]
			}`,
			refreshDuration: time.Duration(1),
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			authzPolicyFile = createTmpPolicyFile(t, name, []byte(test.authzPolicy))
			refreshPolicyDuration = test.refreshDuration
			_, err := NewFileWatcher()
			if fmt.Sprint(err) != fmt.Sprint(test.wantErr) {
				t.Fatalf("NewFileWatcher(%v) returned err: %v, want err: %v", test.authzPolicy, err, test.wantErr)
			}
		})
	}
}
