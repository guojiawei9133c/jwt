package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestHMACGeneration(t *testing.T) {
	tests := []struct {
		name   string
		method SigningMethod
		secret []byte
	}{
		{"HS256", HS256, []byte("test-secret")},
		{"HS384", HS384, []byte("test-secret")},
		{"HS512", HS512, []byte("test-secret")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gen, err := NewGenerator(tt.method, tt.secret)
			if err != nil {
				t.Fatalf("NewGenerator failed: %v", err)
			}

			claims := &Claims{
				Issuer:   "test-issuer",
				Subject:  "test-subject",
				ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
				CustomData: map[string]interface{}{
					"role": "admin",
				},
			}

			token, err := gen.Generate(claims)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}

			if token == "" {
				t.Fatal("Token is empty")
			}

			// Verify token
			verified, err := gen.Verify(token)
			if err != nil {
				t.Fatalf("Verify failed: %v", err)
			}

			if verified.Issuer != claims.Issuer {
				t.Errorf("Issuer mismatch: got %v, want %v", verified.Issuer, claims.Issuer)
			}

			if verified.Subject != claims.Subject {
				t.Errorf("Subject mismatch: got %v, want %v", verified.Subject, claims.Subject)
			}
		})
	}
}

func TestECDSAGeneration(t *testing.T) {
	priKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	gen, err := NewGeneratorWithECDSA(ES256, priKey)
	if err != nil {
		t.Fatalf("NewGeneratorWithECDSA failed: %v", err)
	}

	claims := &Claims{
		Issuer:   "test-issuer",
		Subject:  "test-subject",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token, err := gen.Generate(claims)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	verified, err := gen.Verify(token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if verified.Issuer != claims.Issuer {
		t.Errorf("Issuer mismatch: got %v, want %v", verified.Issuer, claims.Issuer)
	}
}

func TestTokenExpired(t *testing.T) {
	gen, err := NewGenerator(HS256, []byte("test-secret"))
	if err != nil {
		t.Fatalf("NewGenerator failed: %v", err)
	}

	claims := &Claims{
		Issuer:   "test-issuer",
		ExpireAt: time.Now().Add(-1 * time.Hour).Unix(), // 已过期
	}

	token, err := gen.Generate(claims)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	_, err = gen.Verify(token)
	if err != ErrTokenExpired {
		t.Errorf("Expected ErrTokenExpired, got: %v", err)
	}
}

func TestInvalidSignature(t *testing.T) {
	gen1, _ := NewGenerator(HS256, []byte("secret1"))
	gen2, _ := NewGenerator(HS256, []byte("secret2"))

	claims := &Claims{
		Issuer:   "test-issuer",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token, err := gen1.Generate(claims)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	_, err = gen2.Verify(token)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got: %v", err)
	}
}

func TestInvalidToken(t *testing.T) {
	gen, _ := NewGenerator(HS256, []byte("secret"))

	tests := []struct {
		name  string
		token string
	}{
		{"Empty", ""},
		{"MissingParts", "header.payload"},
		{"InvalidBase64", "invalid.invalid.invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := gen.Verify(tt.token)
			if err != ErrInvalidToken && err != ErrInvalidSignature {
				t.Errorf("Expected error for invalid token, got: %v", err)
			}
		})
	}
}

func TestCustomData(t *testing.T) {
	gen, _ := NewGenerator(HS256, []byte("secret"))

	claims := &Claims{
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
		CustomData: map[string]interface{}{
			"user_id":   12345,
			"role":      "admin",
			"active":    true,
			"email":     "test@example.com",
		},
	}

	token, err := gen.Generate(claims)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	verified, err := gen.Verify(token)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if verified.CustomData["user_id"] != float64(12345) {
		t.Errorf("user_id mismatch: got %v, want %v", verified.CustomData["user_id"], 12345)
	}

	if verified.CustomData["role"] != "admin" {
		t.Errorf("role mismatch: got %v, want %v", verified.CustomData["role"], "admin")
	}

	if verified.CustomData["active"] != true {
		t.Errorf("active mismatch: got %v, want %v", verified.CustomData["active"], true)
	}
}

func TestInvalidKey(t *testing.T) {
	_, err := NewGenerator(HS256, []byte(""))
	if err != ErrInvalidKey {
		t.Errorf("Expected ErrInvalidKey, got: %v", err)
	}
}

func TestNotBefore(t *testing.T) {
	gen, _ := NewGenerator(HS256, []byte("secret"))

	// Token that starts in the future
	claims := &Claims{
		NotBefore: time.Now().Add(1 * time.Hour).Unix(),
		ExpireAt:  time.Now().Add(2 * time.Hour).Unix(),
	}

	token, err := gen.Generate(claims)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	_, err = gen.Verify(token)
	if err != ErrTokenExpired {
		t.Errorf("Expected ErrTokenExpired for nbf in future, got: %v", err)
	}
}
