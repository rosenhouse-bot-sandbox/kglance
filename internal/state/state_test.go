package state

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCert(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestFingerprintHashesFirstCertDER(t *testing.T) {
	first, second := testCert(t), testCert(t)
	bundle := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: first}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: second})...)
	got, err := Fingerprint(bundle)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(first)
	if got != hex.EncodeToString(sum[:]) {
		t.Fatalf("got %s", got)
	}
}

func TestFingerprintEmptyCAIsEmpty(t *testing.T) {
	got, err := Fingerprint(nil)
	if err != nil || got != "" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestFingerprintRejectsNonPEM(t *testing.T) {
	if _, err := Fingerprint([]byte("junk")); err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadMissingFileReturnsEmptyState(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "none.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != Version || len(s.Clusters) != 0 {
		t.Fatalf("got %+v", s)
	}
}

func TestSaveLoadRoundTripWith0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	exp := time.Date(2026, 10, 15, 19, 10, 0, 0, time.UTC)
	in := &File{Version: Version, Kubeconfig: "/x/agent.kubeconfig", Expiry: exp, Clusters: []Cluster{{
		Name: "wl1", Role: RoleWorkload, Context: "kind-t1", Server: "https://1.2.3.4", CAFingerprint: "ab",
		Objects: []Object{{APIVersion: "v1", Kind: "Namespace", Name: "kglance"}},
	}}}
	if err := Save(path, in); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	raw, _ := os.ReadFile(path)
	for _, key := range []string{`"caFingerprint"`, `"kubeconfig"`, `"expiry"`, `"apiVersion"`} {
		if !strings.Contains(string(raw), key) {
			t.Errorf("missing %s in %s", key, raw)
		}
	}
	out, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if out.Kubeconfig != in.Kubeconfig || !out.Expiry.Equal(exp) || len(out.Clusters) != 1 || out.Clusters[0].Objects[0].Kind != "Namespace" {
		t.Fatalf("got %+v", out)
	}
}

func TestSaveTightensExistingFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(path, []byte("{}"), 0o644)
	if err := Save(path, &File{Version: Version}); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestLoadRejectsUnknownVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	os.WriteFile(path, []byte(`{"version":99}`), 0o600)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error")
	}
}

func TestPutReplacesByNameAndKeepsOthers(t *testing.T) {
	s := &File{Clusters: []Cluster{{Name: "mgmt", Context: "a"}, {Name: "wl1", Context: "b"}}}
	s.Put(Cluster{Name: "wl1", Context: "c"})
	s.Put(Cluster{Name: "wl2", Context: "d"})
	if len(s.Clusters) != 3 || s.Find("wl1").Context != "c" || s.Find("mgmt").Context != "a" || s.Find("wl2") == nil {
		t.Fatalf("got %+v", s.Clusters)
	}
	if s.Find("nope") != nil {
		t.Fatal("found missing cluster")
	}
}
