package jwt

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateES256(t *testing.T) {
	claims := jwt.MapClaims{
		"iss": "test-issuer",
		"sub": "user123",
		"exp": 9999999999,
	}

	token, privateKey, err := GenerateES256(claims)
	if err != nil {
		t.Fatalf("GenerateES256() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateES256() returned empty token")
	}

	if privateKey == nil {
		t.Error("GenerateES256() returned nil private key")
	}
}

func TestGenerateES384(t *testing.T) {
	claims := jwt.MapClaims{
		"iss": "test-issuer",
		"sub": "user456",
	}

	token, privateKey, err := GenerateES384(claims)
	if err != nil {
		t.Fatalf("GenerateES384() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateES384() returned empty token")
	}

	if privateKey == nil {
		t.Error("GenerateES384() returned nil private key")
	}
}

func TestGenerateES512(t *testing.T) {
	claims := jwt.MapClaims{
		"iss": "test-issuer",
		"sub": "user789",
	}

	token, privateKey, err := GenerateES512(claims)
	if err != nil {
		t.Fatalf("GenerateES512() error = %v", err)
	}

	if token == "" {
		t.Error("GenerateES512() returned empty token")
	}

	if privateKey == nil {
		t.Error("GenerateES512() returned nil private key")
	}
}

func TestVerifyJWT(t *testing.T) {
	claims := jwt.MapClaims{
		"iss": "test-issuer",
		"sub": "user123",
		"exp": 9999999999,
	}

	token, privateKey, err := GenerateES256(claims)
	if err != nil {
		t.Fatalf("GenerateES256() error = %v", err)
	}

	// Verify with correct public key
	valid, err := VerifyJWT(token, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("VerifyJWT() error = %v", err)
	}

	if !valid {
		t.Error("VerifyJWT() returned false for valid token")
	}
}

func TestVerifyJWTInvalidSignature(t *testing.T) {
	claims := jwt.MapClaims{
		"iss": "test-issuer",
		"sub": "user123",
	}

	token, _, err := GenerateES256(claims)
	if err != nil {
		t.Fatalf("GenerateES256() error = %v", err)
	}

	// Generate a different key
	wrongKey, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	// Verify with wrong public key
	valid, err := VerifyJWT(token, &wrongKey.PublicKey)
	if err == nil {
		t.Error("VerifyJWT() should return error for invalid signature")
	}

	if valid {
		t.Error("VerifyJWT() returned true for invalid signature")
	}
}

func TestParseUnverified(t *testing.T) {
	claims := jwt.MapClaims{
		"iss":   "my-app",
		"sub":   "user123",
		"custom": "data",
		"exp":   9999999999,
	}

	token, _, err := GenerateES256(claims)
	if err != nil {
		t.Fatalf("GenerateES256() error = %v", err)
	}

	// Parse without verification
	parsedToken, raw, err := ParseUnverified(token)
	if err != nil {
		t.Fatalf("ParseUnverified() error = %v", err)
	}

	if raw != token {
		t.Error("ParseUnverified() returned different raw token")
	}

	// Check claims
	mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("ParseUnverified() claims is not MapClaims")
	}

	if mapClaims["iss"] != "my-app" {
		t.Errorf("iss = %v, want my-app", mapClaims["iss"])
	}

	if mapClaims["sub"] != "user123" {
		t.Errorf("sub = %v, want user123", mapClaims["sub"])
	}

	if mapClaims["custom"] != "data" {
		t.Errorf("custom = %v, want data", mapClaims["custom"])
	}
}

func TestParseUnverifiedInvalidToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"Empty", ""},
		{"Invalid", "not.a.jwt"},
		{"MissingParts", "header.payload"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseUnverified(tt.token)
			if err == nil {
				t.Error("ParseUnverified() should return error for invalid token")
			}
		})
	}
}

func TestParseUnverifiedThenVerify(t *testing.T) {
	// Simulate two-phase verification: decode then verify

	// Phase 1: Generate token
	claims := jwt.MapClaims{
		"iss": "tenant-123",
		"sub": "user456",
		"exp": 9999999999,
	}

	token, privateKey, err := GenerateES256(claims)
	if err != nil {
		t.Fatalf("GenerateES256() error = %v", err)
	}

	// Phase 2: Parse without verification to get issuer
	parsedToken, _, err := ParseUnverified(token)
	if err != nil {
		t.Fatalf("ParseUnverified() error = %v", err)
	}

	mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("ParseUnverified() claims is not MapClaims")
	}

	// Extract issuer to lookup key
	issuer := mapClaims["iss"]
	if issuer != "tenant-123" {
		t.Errorf("issuer = %v, want tenant-123", issuer)
	}

	// In real scenario: key := keyStore.Lookup(issuer)
	// For this test, we use the privateKey we already have

	// Phase 3: Verify signature
	valid, err := VerifyJWT(token, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("VerifyJWT() error = %v", err)
	}

	if !valid {
		t.Error("VerifyJWT() returned false for valid token")
	}
}
