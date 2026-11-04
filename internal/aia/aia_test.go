package aia

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

type pair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func genCA(t *testing.T, cn string) pair {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return pair{cert: c, key: k, der: der}
}

func genIssued(t *testing.T, parent pair, cn string, aiaURIs []string, isCA bool) pair {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(90 * 24 * time.Hour),
		DNSNames:              []string{cn},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IssuingCertificateURL: aiaURIs,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent.cert, &k.PublicKey, parent.key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return pair{cert: c, key: k, der: der}
}

func writePEM(t *testing.T, path string, ders ...[]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, der := range ders {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnalyze_CompleteChainVerifies(t *testing.T) {
	root := genCA(t, "Test Root")
	inter := genIssued(t, root, "Test Intermediate", nil, true)
	leaf := genIssued(t, inter, "example.com", []string{"http://aia.example.com/ca.crt"}, false)

	dir := t.TempDir()
	leafPath := filepath.Join(dir, "leaf.pem")
	chainPath := filepath.Join(dir, "chain.pem")
	writePEM(t, leafPath, leaf.der)
	writePEM(t, chainPath, inter.der)

	pool := x509.NewCertPool()
	pool.AddCert(root.cert)

	r, err := Analyze(Options{CertFile: leafPath, ChainFile: chainPath, Roots: pool})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !r.HasAIA {
		t.Error("expected HasAIA=true")
	}
	if !r.ChainCompleteAgainstSystemRoots {
		t.Errorf("expected chain complete; VerifyError=%q", r.VerifyError)
	}
	if r.WouldNeedAIAFetch {
		t.Error("should not need AIA fetch when chain is complete")
	}
	if r.PresentedIntermediateCount != 1 {
		t.Errorf("intermediates = %d, want 1", r.PresentedIntermediateCount)
	}
}

func TestAnalyze_IncompleteChainFails(t *testing.T) {
	root := genCA(t, "Test Root")
	inter := genIssued(t, root, "Test Intermediate", nil, true)
	leaf := genIssued(t, inter, "example.com", []string{"http://aia.example.com/ca.crt"}, false)

	dir := t.TempDir()
	leafPath := filepath.Join(dir, "leaf.pem")
	writePEM(t, leafPath, leaf.der)

	pool := x509.NewCertPool()
	pool.AddCert(root.cert)

	r, err := Analyze(Options{CertFile: leafPath, Roots: pool})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if r.ChainCompleteAgainstSystemRoots {
		t.Fatal("expected incomplete chain")
	}
	if !r.WouldNeedAIAFetch {
		t.Error("expected WouldNeedAIAFetch=true since leaf has AIA")
	}
	if r.PresentedIntermediateCount != 0 {
		t.Errorf("intermediates = %d, want 0", r.PresentedIntermediateCount)
	}
}

func TestAnalyze_NoAIANotFatalIfComplete(t *testing.T) {
	root := genCA(t, "Test Root")
	inter := genIssued(t, root, "Test Intermediate", nil, true)
	leaf := genIssued(t, inter, "example.com", nil, false)

	dir := t.TempDir()
	leafPath := filepath.Join(dir, "leaf.pem")
	chainPath := filepath.Join(dir, "chain.pem")
	writePEM(t, leafPath, leaf.der)
	writePEM(t, chainPath, inter.der)

	pool := x509.NewCertPool()
	pool.AddCert(root.cert)

	r, err := Analyze(Options{CertFile: leafPath, ChainFile: chainPath, Roots: pool})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if r.HasAIA {
		t.Error("expected HasAIA=false")
	}
	if !r.ChainCompleteAgainstSystemRoots {
		t.Errorf("expected chain complete without AIA; VerifyError=%q", r.VerifyError)
	}
}

func TestLoadCerts_MalformedFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bogus.pem")
	os.WriteFile(p, []byte("not a cert"), 0o600)
	if _, err := loadCerts(p); err == nil {
		t.Fatal("expected error on malformed PEM")
	}
}
