package kube

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testCAPEM(t *testing.T) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ca"}, NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestConnectInlinesCAFileAndKeepsServer(t *testing.T) {
	dir := t.TempDir()
	ca := testCAPEM(t)
	os.WriteFile(filepath.Join(dir, "ca.crt"), ca, 0o600)
	kc := filepath.Join(dir, "config")
	os.WriteFile(kc, []byte(`apiVersion: v1
kind: Config
clusters:
- name: c1
  cluster: {server: "https://10.0.0.1:6443", certificate-authority: ca.crt, tls-server-name: api.local}
- name: c2
  cluster: {server: "https://10.0.0.2:6443", insecure-skip-tls-verify: true}
users:
- name: u
  user: {token: admin-token}
contexts:
- name: one
  context: {cluster: c1, user: u}
- name: two
  context: {cluster: c2, user: u}
current-context: two
`), 0o600)

	c, err := Connect(kc, "one")
	if err != nil {
		t.Fatal(err)
	}
	if c.Context != "one" || c.Cluster.Server != "https://10.0.0.1:6443" || string(c.Cluster.CertificateAuthorityData) != string(ca) ||
		c.Cluster.CertificateAuthority != "" || c.Cluster.TLSServerName != "api.local" || c.Client == nil {
		t.Fatalf("got %+v", c.Cluster)
	}
	c2, err := Connect(kc, "two")
	if err != nil || !c2.Cluster.InsecureSkipTLSVerify || c2.Cluster.Server != "https://10.0.0.2:6443" {
		t.Fatalf("got %+v %v", c2, err)
	}
	if _, err := Connect(kc, "missing"); err == nil {
		t.Fatal("expected error for missing context")
	}
}
