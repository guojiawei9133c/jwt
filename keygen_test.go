package jwt

import (
	"strings"
	"testing"
)

func TestGenerateHMACKey256(t *testing.T) {
	key, err := GenerateHMACKey256()
	if err != nil {
		t.Fatalf("GenerateHMACKey256() error = %v", err)
	}
	if len(key) != 32 {
		t.Errorf("GenerateHMACKey256() len = %v, want 32", len(key))
	}
}

func TestGenerateHMACKey384(t *testing.T) {
	key, err := GenerateHMACKey384()
	if err != nil {
		t.Fatalf("GenerateHMACKey384() error = %v", err)
	}
	if len(key) != 48 {
		t.Errorf("GenerateHMACKey384() len = %v, want 48", len(key))
	}
}

func TestGenerateHMACKey512(t *testing.T) {
	key, err := GenerateHMACKey512()
	if err != nil {
		t.Fatalf("GenerateHMACKey512() error = %v", err)
	}
	if len(key) != 64 {
		t.Errorf("GenerateHMACKey512() len = %v, want 64", len(key))
	}
}

func TestGenerateHMACKeyWithGenerator(t *testing.T) {
	// Test HS256
	key256, err := GenerateHMACKey256()
	if err != nil {
		t.Fatalf("GenerateHMACKey256() error = %v", err)
	}

	gen, err := NewGenerator(HS256, key256)
	if err != nil {
		t.Fatalf("NewGenerator() error = %v", err)
	}

	claims := &Claims{
		Issuer:   "test",
		Subject:  "user123",
		ExpireAt: 9999999999,
	}

	token, err := gen.Generate(claims)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	verifiedClaims, err := gen.Verify(token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if verifiedClaims.Subject != claims.Subject {
		t.Errorf("Subject = %v, want %v", verifiedClaims.Subject, claims.Subject)
	}
}

func TestGenerateECDSAKeyP256(t *testing.T) {
	key, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}
	if key == nil {
		t.Error("PrivateKey is nil")
	}
}

func TestGenerateECDSAKeyP384(t *testing.T) {
	key, err := GenerateECDSAKeyP384()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP384() error = %v", err)
	}
	if key == nil {
		t.Error("PrivateKey is nil")
	}
}

func TestGenerateECDSAKeyP521(t *testing.T) {
	key, err := GenerateECDSAKeyP521()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP521() error = %v", err)
	}
	if key == nil {
		t.Error("PrivateKey is nil")
	}
}

func TestGenerateECDSAKeyWithGenerator(t *testing.T) {
	key, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	gen, err := NewGeneratorWithECDSA(ES256, key)
	if err != nil {
		t.Fatalf("NewGeneratorWithECDSA() error = %v", err)
	}
	gen.SetPublicKey(&key.PublicKey)

	claims := &Claims{
		Issuer:   "test",
		Subject:  "user123",
		ExpireAt: 9999999999,
	}

	token, err := gen.Generate(claims)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	verifiedClaims, err := gen.Verify(token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if verifiedClaims.Subject != claims.Subject {
		t.Errorf("Subject = %v, want %v", verifiedClaims.Subject, claims.Subject)
	}
}

func TestExportPrivateKeyPEM(t *testing.T) {
	key, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	privPEM, err := ExportPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("ExportPrivateKeyPEM() error = %v", err)
	}
	if !strings.Contains(privPEM, "EC PRIVATE KEY") {
		t.Error("ExportPrivateKeyPEM() missing EC PRIVATE KEY header")
	}
}

func TestExportPublicKeyPEM(t *testing.T) {
	key, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	pubPEM, err := ExportPublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("ExportPublicKeyPEM() error = %v", err)
	}
	if !strings.Contains(pubPEM, "PUBLIC KEY") {
		t.Error("ExportPublicKeyPEM() missing PUBLIC KEY header")
	}
}

func TestGenerateECDSAKeyPair(t *testing.T) {
	// Tests covered by TestGenerateECDSAKeyP256/P384/P521
}

func TestECDSAKeyPairPEM(t *testing.T) {
	key, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	// Test Private Key PEM
	privPEM, err := ExportPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("ExportPrivateKeyPEM() error = %v", err)
	}
	if !strings.Contains(privPEM, "EC PRIVATE KEY") {
		t.Error("ExportPrivateKeyPEM() missing EC PRIVATE KEY header")
	}

	// Test Public Key PEM
	pubPEM, err := ExportPublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("ExportPublicKeyPEM() error = %v", err)
	}
	if !strings.Contains(pubPEM, "PUBLIC KEY") {
		t.Error("ExportPublicKeyPEM() missing PUBLIC KEY header")
	}
}

func TestParseECDSAFromPEM(t *testing.T) {
	key, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	privPEM, err := ExportPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("ExportPrivateKeyPEM() error = %v", err)
	}

	privKey, err := ParseECDSAFromPEM([]byte(privPEM))
	if err != nil {
		t.Fatalf("ParseECDSAFromPEM() error = %v", err)
	}
	if privKey == nil {
		t.Error("ParseECDSAFromPEM() returned nil key")
	}
}

func TestParsePublicKeyFromPEM(t *testing.T) {
	key, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	pubPEM, err := ExportPublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("ExportPublicKeyPEM() error = %v", err)
	}

	pubKey, err := ParsePublicKeyFromPEM([]byte(pubPEM))
	if err != nil {
		t.Fatalf("ParsePublicKeyFromPEM() error = %v", err)
	}
	if pubKey == nil {
		t.Error("ParsePublicKeyFromPEM() returned nil key")
	}
}

func TestRoundTripECDSAPEM(t *testing.T) {
	// Generate key pair
	key, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	// Export to PEM
	privPEM, err := ExportPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("ExportPrivateKeyPEM() error = %v", err)
	}

	pubPEM, err := ExportPublicKeyPEM(&key.PublicKey)
	if err != nil {
		t.Fatalf("ExportPublicKeyPEM() error = %v", err)
	}

	// Import from PEM
	privKey, err := ParseECDSAFromPEM([]byte(privPEM))
	if err != nil {
		t.Fatalf("ParseECDSAFromPEM() error = %v", err)
	}

	pubKey, err := ParsePublicKeyFromPEM([]byte(pubPEM))
	if err != nil {
		t.Fatalf("ParsePublicKeyFromPEM() error = %v", err)
	}

	// Test with JWT
	gen, err := NewGeneratorWithECDSA(ES256, privKey)
	if err != nil {
		t.Fatalf("NewGeneratorWithECDSA() error = %v", err)
	}
	gen.SetPublicKey(pubKey)

	claims := &Claims{
		Issuer:   "test",
		Subject:  "user123",
		ExpireAt: 9999999999,
	}

	token, err := gen.Generate(claims)
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	verifiedClaims, err := gen.Verify(token)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if verifiedClaims.Subject != claims.Subject {
		t.Errorf("Subject = %v, want %v", verifiedClaims.Subject, claims.Subject)
	}
}

func TestParseECDSAInvalidPEM(t *testing.T) {
	tests := []struct {
		name    string
		pemData []byte
	}{
		{"Invalid PEM", []byte("not a pem")},
		{"Wrong Type", []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAyGW==\n-----END RSA PRIVATE KEY-----")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseECDSAFromPEM(tt.pemData)
			if err == nil {
				t.Error("ParseECDSAFromPEM() should return error for invalid PEM")
			}
		})
	}
}
