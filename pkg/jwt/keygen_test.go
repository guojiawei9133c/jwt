package jwt

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestGenerateHMACKey(t *testing.T) {
	tests := []struct {
		name    string
		bits    int
		wantLen int
	}{
		{"HS256", 256, 32},  // 32 bytes
		{"HS384", 384, 48},  // 48 bytes
		{"HS512", 512, 64},  // 64 bytes
		{"Custom", 128, 16}, // 16 bytes
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateHMACKey(tt.bits)
			if err != nil {
				t.Fatalf("GenerateHMACKey() error = %v", err)
			}
			if len(key) != tt.wantLen {
				t.Errorf("GenerateHMACKey() len = %v, want %v", len(key), tt.wantLen)
			}
		})
	}
}

func TestGenerateHMACKeyInvalid(t *testing.T) {
	_, err := GenerateHMACKey(-1)
	if err == nil {
		t.Error("GenerateHMACKey() with negative bits should return error")
	}

	_, err = GenerateHMACKey(0)
	if err == nil {
		t.Error("GenerateHMACKey() with 0 bits should return error")
	}
}

func TestGenerateHMACKeyHex(t *testing.T) {
	keyHex, err := GenerateHMACKeyHex(256)
	if err != nil {
		t.Fatalf("GenerateHMACKeyHex() error = %v", err)
	}
	if len(keyHex) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("GenerateHMACKeyHex() len = %v, want 64", len(keyHex))
	}
}

func TestGenerateHMACKeyBase64(t *testing.T) {
	key, err := GenerateHMACKeyBase64(256)
	if err != nil {
		t.Fatalf("GenerateHMACKeyBase64() error = %v", err)
	}
	if len(key) == 0 {
		t.Error("GenerateHMACKeyBase64() returned empty string")
	}
	// Verify it's valid base64
	_, err = base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Errorf("GenerateHMACKeyBase64() produced invalid base64: %v", err)
	}
}

func TestGenerateHMACKeyWithGenerator(t *testing.T) {
	// Test that generated key works with NewGenerator
	key, err := GenerateHMACKey(256)
	if err != nil {
		t.Fatalf("GenerateHMACKey() error = %v", err)
	}

	gen, err := NewGenerator(HS256, key)
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

func TestGenerateECDSAKeyPair(t *testing.T) {
	curves := []string{"P256", "P384", "P521"}

	for _, curve := range curves {
		t.Run(curve, func(t *testing.T) {
			kp, err := GenerateECDSAKeyPair(curve)
			if err != nil {
				t.Fatalf("GenerateECDSAKeyPair() error = %v", err)
			}
			if kp.PrivateKey == nil {
				t.Error("PrivateKey is nil")
			}
			if kp.PublicKey == nil {
				t.Error("PublicKey is nil")
			}
		})
	}
}

func TestECDSAKeyPairPEM(t *testing.T) {
	kp, err := GenerateECDSAKeyPair("P256")
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair() error = %v", err)
	}

	// Test Private Key PEM
	privPEM, err := kp.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("PrivateKeyPEM() error = %v", err)
	}
	if !strings.Contains(privPEM, "EC PRIVATE KEY") {
		t.Error("PrivateKeyPEM() missing EC PRIVATE KEY header")
	}

	// Test Public Key PEM
	pubPEM, err := kp.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM() error = %v", err)
	}
	if !strings.Contains(pubPEM, "PUBLIC KEY") {
		t.Error("PublicKeyPEM() missing PUBLIC KEY header")
	}
}

func TestParseECDSAFromPEM(t *testing.T) {
	kp1, err := GenerateECDSAKeyPair("P256")
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair() error = %v", err)
	}

	privPEM, err := kp1.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("PrivateKeyPEM() error = %v", err)
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
	kp1, err := GenerateECDSAKeyPair("P256")
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair() error = %v", err)
	}

	pubPEM, err := kp1.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM() error = %v", err)
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
	kp1, err := GenerateECDSAKeyPair("P256")
	if err != nil {
		t.Fatalf("GenerateECDSAKeyPair() error = %v", err)
	}

	// Export to PEM
	privPEM, err := kp1.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("PrivateKeyPEM() error = %v", err)
	}

	pubPEM, err := kp1.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM() error = %v", err)
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
