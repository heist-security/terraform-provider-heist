package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/heist-security/heist-go/heist"
)

// TestContractSnapshot checks that the committed OpenAPI snapshot matches its
// lock file and the contract version of the pinned SDK release.
func TestContractSnapshot(t *testing.T) {
	var lock struct {
		Version string `json:"version"`
		URL     string `json:"url"`
		SHA256  string `json:"sha256"`
	}
	data, err := os.ReadFile("../../api/openapi.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile("../../api/openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(snapshot)
	if got := hex.EncodeToString(sum[:]); got != lock.SHA256 {
		t.Errorf("api/openapi.json SHA-256 is %s, lock file says %s", got, lock.SHA256)
	}
	if want := "https://openapi.heist.security/" + lock.Version + "/openapi.json"; lock.URL != want {
		t.Errorf("lock URL is %q, want %q", lock.URL, want)
	}
	if lock.Version != heist.APIVersion {
		t.Errorf("snapshot version %s does not match the pinned SDK's heist.APIVersion %s; update the snapshot with the SDK", lock.Version, heist.APIVersion)
	}
}
