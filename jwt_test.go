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

func TestVerifyBearer(t *testing.T) {
	gen, _ := NewGenerator(HS256, []byte("secret"))

	claims := &Claims{
		Issuer:   "test",
		Subject:  "user123",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token, err := gen.Generate(claims)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	tests := []struct {
		name           string
		authorization  string
		wantSubject    string
		wantErr        bool
	}{
		{"ValidBearer", "Bearer " + token, "user123", false},
		{"ValidBearerWithSpace", "Bearer  " + token, "user123", false},
		{"LowerCaseBearer", "bearer " + token, "user123", false},
		{"MixedCaseBearer", "BEARER " + token, "user123", false},
		{"NoBearer", token, "user123", false}, // 兼容直接传 token
		{"EmptyString", "", "", true},
		{"OnlyBearer", "Bearer", "", true},
		{"BearerEmpty", "Bearer ", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			verified, err := gen.VerifyBearer(tt.authorization)
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyBearer failed: %v", err)
			}
			if verified.Subject != tt.wantSubject {
				t.Errorf("Subject = %v, want %v", verified.Subject, tt.wantSubject)
			}
		})
	}
}

func TestVerifyBearerInvalidSignature(t *testing.T) {
	gen1, _ := NewGenerator(HS256, []byte("secret1"))
	gen2, _ := NewGenerator(HS256, []byte("secret2"))

	claims := &Claims{
		Subject:  "user123",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token, _ := gen1.Generate(claims)

	_, err := gen2.VerifyBearer("Bearer " + token)
	if err != ErrInvalidSignature {
		t.Errorf("Expected ErrInvalidSignature, got: %v", err)
	}
}

func TestGenerateDoesNotModifyClaims(t *testing.T) {
	gen, _ := NewGenerator(HS256, []byte("secret"))

	originalClaims := &Claims{
		Issuer:   "test",
		Subject:  "user123",
		// IssuedAt = 0, ExpireAt = 0
	}

	originalIssuedAt := originalClaims.IssuedAt
	originalExpireAt := originalClaims.ExpireAt

	// Generate token
	token, _ := gen.Generate(originalClaims)

	// Claims should not be modified
	if originalClaims.IssuedAt != originalIssuedAt {
		t.Errorf("IssuedAt was modified: %v", originalClaims.IssuedAt)
	}
	if originalClaims.ExpireAt != originalExpireAt {
		t.Errorf("ExpireAt was modified: %v", originalClaims.ExpireAt)
	}

	// Token should be generated
	if token == "" {
		t.Error("Token should not be empty")
	}

	// Generate again with same claims - should produce same result in same second
	token2, _ := gen.Generate(originalClaims)
	if token2 == "" {
		t.Error("Second token should not be empty")
	}
}

func TestVerifyWithKeyStoreInvalidAlgorithm(t *testing.T) {
	store := NewMemoryKeyStore()

	// Create ECDSA token
	priKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gen, _ := NewGeneratorWithECDSA(ES256, priKey)

	claims := &Claims{
		ID:       "test-jti",
		Subject:  "user123",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token, _ := gen.Generate(claims)

	// Try to verify with KeyStore (should fail - not HMAC)
	_, err := VerifyWithKeyStore(token, store)
	if err == nil {
		t.Error("Expected error for ECDSA token with KeyStore")
	}
}

func TestMemoryKeyStoreClose(t *testing.T) {
	store := NewMemoryKeyStore()

	store.Set("jti1", []byte("secret1"))

	// Should work before close
	secret, ok := store.Get("jti1")
	if !ok || string(secret) != "secret1" {
		t.Error("Get failed before Close")
	}

	// Close should not error
	err := store.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestDecode(t *testing.T) {
	gen, _ := NewGenerator(HS256, []byte("secret"))

	claims := &Claims{
		Issuer:   "test-issuer",
		Subject:  "user123",
		Audience: "my-api",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
		CustomData: map[string]interface{}{
			"role": "admin",
		},
	}

	tokenString, err := gen.Generate(claims)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Decode without verification
	token, err := Decode(tokenString)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Check Raw
	if token.Raw != tokenString {
		t.Error("Raw token mismatch")
	}

	// Check Header
	if token.Header == nil {
		t.Fatal("Header is nil")
	}
	if token.Header["typ"] != "JWT" {
		t.Errorf("Header typ = %v, want JWT", token.Header["typ"])
	}
	if token.Header["alg"] != "HS256" {
		t.Errorf("Header alg = %v, want HS256", token.Header["alg"])
	}

	// Check Claims
	if token.Claims == nil {
		t.Fatal("Claims is nil")
	}
	if token.Claims.Issuer != claims.Issuer {
		t.Errorf("Issuer = %v, want %v", token.Claims.Issuer, claims.Issuer)
	}
	if token.Claims.Subject != claims.Subject {
		t.Errorf("Subject = %v, want %v", token.Claims.Subject, claims.Subject)
	}
	if token.Claims.Audience != claims.Audience {
		t.Errorf("Audience = %v, want %v", token.Claims.Audience, claims.Audience)
	}
	if token.Claims.CustomData["role"] != "admin" {
		t.Errorf("CustomData role = %v, want admin", token.Claims.CustomData["role"])
	}

	// Check Signature
	if token.Signature == "" {
		t.Error("Signature is empty")
	}
}

func TestDecodeInvalidToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
	}{
		{"Empty", ""},
		{"MissingParts", "header.payload"},
		{"InvalidBase64", "invalid.invalid.invalid"},
		{"OnlyHeader", "abc.def"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.token)
			if err == nil {
				t.Error("Expected error for invalid token")
			}
		})
	}
}

func TestDecodeECDSAToken(t *testing.T) {
	priKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	gen, _ := NewGeneratorWithECDSA(ES256, priKey)

	claims := &Claims{
		Issuer:   "ecdsa-issuer",
		Subject:  "user456",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	tokenString, _ := gen.Generate(claims)

	token, err := Decode(tokenString)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if token.Claims.Issuer != claims.Issuer {
		t.Errorf("Issuer = %v, want %v", token.Claims.Issuer, claims.Issuer)
	}
	if token.Header["alg"] != "ES256" {
		t.Errorf("Header alg = %v, want ES256", token.Header["alg"])
	}
}

func TestDecodeThenVerify(t *testing.T) {
	// Phase 1: Generate token
	gen, _ := NewGenerator(HS256, []byte("secret"))
	claims := &Claims{
		Issuer:   "my-app",
		Subject:  "user123",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
	}
	tokenString, _ := gen.Generate(claims)

	// Phase 2: Decode without key (simulate multi-tenant scenario)
	token, err := Decode(tokenString)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	// Use decoded info to lookup key (simulated)
	issuer := token.Claims.Issuer
	if issuer != "my-app" {
		t.Errorf("Issuer = %v, want my-app", issuer)
	}
	// In real scenario: key := keyStore.Lookup(issuer)
	// For this test, we already have the key

	// Phase 3: Verify with key
	verified, err := gen.Verify(token.Raw)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if verified.Subject != claims.Subject {
		t.Errorf("Subject = %v, want %v", verified.Subject, claims.Subject)
	}
}

func TestGenerateWithKey(t *testing.T) {
	store := NewMemoryKeyStore()
	gen, _ := NewGenerator(HS256, []byte("dummy")) // method reference

	claims := &Claims{
		Issuer:   "test-app",
		Subject:  "user123",
		ID:       "unique-jti-123",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	// Generate token with per-jti key
	token, err := GenerateWithKey(store, gen, claims, GenerateHMACKey256)
	if err != nil {
		t.Fatalf("GenerateWithKey failed: %v", err)
	}

	// Verify key was stored
	secret, ok := store.Get("unique-jti-123")
	if !ok {
		t.Fatal("Key was not stored in KeyStore")
	}
	if len(secret) != 32 {
		t.Errorf("Key size = %v, want 32", len(secret))
	}

	// Verify token using KeyStore
	verified, err := VerifyWithKeyStore(token, store)
	if err != nil {
		t.Fatalf("VerifyWithKeyStore failed: %v", err)
	}

	if verified.Subject != claims.Subject {
		t.Errorf("Subject = %v, want %v", verified.Subject, claims.Subject)
	}
}

func TestGenerateWithKeyAndTTL(t *testing.T) {
	store := NewMemoryKeyStore()
	gen, _ := NewGenerator(HS256, []byte("dummy"))

	claims := &Claims{
		Issuer:   "test-app",
		Subject:  "user456",
		ID:       "expiring-jti",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	// Generate token with 100ms TTL
	token, err := GenerateWithKeyAndTTL(store, gen, claims, GenerateHMACKey256, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("GenerateWithKeyAndTTL failed: %v", err)
	}

	// Should verify immediately
	_, err = VerifyWithKeyStore(token, store)
	if err != nil {
		t.Fatalf("VerifyWithKeyStore failed immediately: %v", err)
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should fail after expiration
	_, err = VerifyWithKeyStore(token, store)
	if err != ErrInvalidKey {
		t.Errorf("Expected ErrInvalidKey after expiration, got: %v", err)
	}
}

func TestGenerateWithKeyMissingJTI(t *testing.T) {
	store := NewMemoryKeyStore()
	gen, _ := NewGenerator(HS256, []byte("dummy"))

	claims := &Claims{
		Issuer:   "test-app",
		Subject:  "user789",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
		// ID is empty
	}

	_, err := GenerateWithKey(store, gen, claims, GenerateHMACKey256)
	if err != ErrInvalidKey {
		t.Errorf("Expected ErrInvalidKey, got: %v", err)
	}
}

func TestVerifyWithKeyStoreInvalidJTI(t *testing.T) {
	store := NewMemoryKeyStore()
	gen, _ := NewGenerator(HS256, []byte("secret"))

	claims := &Claims{
		Issuer:   "test-app",
		Subject:  "user999",
		ID:       "unknown-jti",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
	}

	token, _ := gen.Generate(claims)

	// Key not in store
	_, err := VerifyWithKeyStore(token, store)
	if err != ErrInvalidKey {
		t.Errorf("Expected ErrInvalidKey, got: %v", err)
	}
}
