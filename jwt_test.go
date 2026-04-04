package jwt

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims 自定义 Claims 类型，用于测试泛型支持
type CustomClaims struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func TestGenerateES256(t *testing.T) {
	t.Run("MapClaims", func(t *testing.T) {
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
	})

	t.Run("CustomClaims", func(t *testing.T) {
		claims := CustomClaims{
			Name:  "John Doe",
			Email: "john@example.com",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-app",
				Subject:   "user123",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			},
		}

		token, privateKey, err := GenerateES256(claims)
		if err != nil {
			t.Fatalf("GenerateES256() with CustomClaims error = %v", err)
		}

		if token == "" {
			t.Error("GenerateES256() returned empty token")
		}

		if privateKey == nil {
			t.Error("GenerateES256() returned nil private key")
		}

		// 验证生成的 token 可以被解析
		parsedToken, err := ParseUnverified(token)
		if err != nil {
			t.Fatalf("ParseUnverified() error = %v", err)
		}

		mapClaims, ok := parsedToken.Claims.(jwt.MapClaims)
		if !ok {
			t.Fatal("Parsed claims is not MapClaims")
		}

		if mapClaims["name"] != "John Doe" {
			t.Errorf("name = %v, want John Doe", mapClaims["name"])
		}

		if mapClaims["email"] != "john@example.com" {
			t.Errorf("email = %v, want john@example.com", mapClaims["email"])
		}
	})
}

func TestGenerateES384(t *testing.T) {
	t.Run("MapClaims", func(t *testing.T) {
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
	})

	t.Run("CustomClaims", func(t *testing.T) {
		claims := CustomClaims{
			Name:  "Jane Doe",
			Email: "jane@example.com",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-app",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			},
		}

		token, privateKey, err := GenerateES384(claims)
		if err != nil {
			t.Fatalf("GenerateES384() with CustomClaims error = %v", err)
		}

		if token == "" {
			t.Error("GenerateES384() returned empty token")
		}

		if privateKey == nil {
			t.Error("GenerateES384() returned nil private key")
		}
	})
}

func TestGenerateES512(t *testing.T) {
	t.Run("MapClaims", func(t *testing.T) {
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
	})

	t.Run("CustomClaims", func(t *testing.T) {
		claims := CustomClaims{
			Name:  "Bob Smith",
			Email: "bob@example.com",
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "test-app",
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			},
		}

		token, privateKey, err := GenerateES512(claims)
		if err != nil {
			t.Fatalf("GenerateES512() with CustomClaims error = %v", err)
		}

		if token == "" {
			t.Error("GenerateES512() returned empty token")
		}

		if privateKey == nil {
			t.Error("GenerateES512() returned nil private key")
		}
	})
}

func TestVerifyJWT(t *testing.T) {
	t.Run("ES256 valid token", func(t *testing.T) {
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
	})

	t.Run("ES384 valid token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "test-issuer",
			"sub": "user456",
			"exp": 9999999999,
		}

		token, privateKey, err := GenerateES384(claims)
		if err != nil {
			t.Fatalf("GenerateES384() error = %v", err)
		}

		valid, err := VerifyJWT(token, &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("VerifyJWT() error = %v", err)
		}

		if !valid {
			t.Error("VerifyJWT() returned false for valid ES384 token")
		}
	})

	t.Run("ES512 valid token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "test-issuer",
			"sub": "user789",
			"exp": 9999999999,
		}

		token, privateKey, err := GenerateES512(claims)
		if err != nil {
			t.Fatalf("GenerateES512() error = %v", err)
		}

		valid, err := VerifyJWT(token, &privateKey.PublicKey)
		if err != nil {
			t.Fatalf("VerifyJWT() error = %v", err)
		}

		if !valid {
			t.Error("VerifyJWT() returned false for valid ES512 token")
		}
	})

	t.Run("Expired token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "test-issuer",
			"sub": "user123",
			"exp": float64(time.Now().Add(-1 * time.Hour).Unix()), // 已过期
		}

		token, privateKey, err := GenerateES256(claims)
		if err != nil {
			t.Fatalf("GenerateES256() error = %v", err)
		}

		// Verify expired token - should return false or error
		valid, err := VerifyJWT(token, &privateKey.PublicKey)
		if err != nil {
			// golang-jwt 返回错误表示 token 过期
			if !strings.Contains(err.Error(), "expired") {
				t.Errorf("Expected expired error, got: %v", err)
			}
		}
		if valid {
			t.Error("VerifyJWT() returned true for expired token")
		}
	})

	t.Run("Invalid token format", func(t *testing.T) {
		tests := []struct {
			name  string
			token string
		}{
			{"Empty", ""},
			{"Invalid", "not.a.jwt.token"},
			{"Missing parts", "header.payload"},
			{"Only header", "abc.def"},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				key, _ := GenerateECDSAKeyP256()
				valid, err := VerifyJWT(tt.token, &key.PublicKey)
				if err == nil {
					t.Error("VerifyJWT() should return error for invalid token format")
				}
				if valid {
					t.Error("VerifyJWT() returned true for invalid token")
				}
			})
		}
	})

	t.Run("Non-ECDSA algorithm", func(t *testing.T) {
		// 创建一个使用 HMAC 算法的 token
		hmacToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.4Adcj3mYcZgACderzPfBqyfgqE9k7Tqf_XhGjyqjXOA"

		key, _ := GenerateECDSAKeyP256()
		valid, err := VerifyJWT(hmacToken, &key.PublicKey)

		if err == nil {
			t.Error("VerifyJWT() should return error for HMAC token")
		}
		if valid {
			t.Error("VerifyJWT() returned true for HMAC token")
		}
	})

	t.Run("Nil public key", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "test-issuer",
			"exp": 9999999999,
		}

		token, _, err := GenerateES256(claims)
		if err != nil {
			t.Fatalf("GenerateES256() error = %v", err)
		}

		// 使用 nil 公钥应该会 panic 或返回错误
		defer func() {
			if r := recover(); r == nil {
				t.Error("VerifyJWT() should panic with nil public key")
			}
		}()

		_, _ = VerifyJWT(token, nil)
	})
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
	t.Run("Parse ES256 token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss":    "my-app",
			"sub":    "user123",
			"custom": "data",
			"exp":    9999999999,
		}

		token, _, err := GenerateES256(claims)
		if err != nil {
			t.Fatalf("GenerateES256() error = %v", err)
		}

		// Parse without verification
		parsedToken, err := ParseUnverified(token)
		if err != nil {
			t.Fatalf("ParseUnverified() error = %v", err)
		}

		if parsedToken.Raw != token {
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

		// 检查 Token 字段完整性
		if parsedToken.Header == nil {
			t.Error("ParseUnverified() returned nil Header")
		}
		if parsedToken.Method == nil {
			t.Error("ParseUnverified() returned nil Method")
		}
		if parsedToken.Signature == nil {
			t.Error("ParseUnverified() returned nil Signature")
		}
	})

	t.Run("Parse ES384 token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "my-app",
			"sub": "user456",
		}

		token, _, err := GenerateES384(claims)
		if err != nil {
			t.Fatalf("GenerateES384() error = %v", err)
		}

		parsedToken, err := ParseUnverified(token)
		if err != nil {
			t.Fatalf("ParseUnverified() error = %v", err)
		}

		// 验证算法字段
		if parsedToken.Header["alg"] != "ES384" {
			t.Errorf("alg = %v, want ES384", parsedToken.Header["alg"])
		}
	})

	t.Run("Parse ES512 token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "my-app",
			"sub": "user789",
		}

		token, _, err := GenerateES512(claims)
		if err != nil {
			t.Fatalf("GenerateES512() error = %v", err)
		}

		parsedToken, err := ParseUnverified(token)
		if err != nil {
			t.Fatalf("ParseUnverified() error = %v", err)
		}

		// 验证算法字段
		if parsedToken.Header["alg"] != "ES512" {
			t.Errorf("alg = %v, want ES512", parsedToken.Header["alg"])
		}
	})

	t.Run("Missing alg field", func(t *testing.T) {
		// 构造一个缺少 alg 字段的 token
		header := `{"typ":"JWT"}`
		claims := `{"sub":"user"}`
		signature := "signature"

		brokenToken := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(claims)) + "." + signature

		_, err := ParseUnverified(brokenToken)
		if err == nil {
			t.Error("ParseUnverified() should return error for missing alg field")
		}
		if !strings.Contains(err.Error(), "alg") {
			t.Errorf("Error should mention alg field, got: %v", err)
		}
	})

	t.Run("Unsupported algorithm", func(t *testing.T) {
		// 构造一个使用不支持的算法的 token
		header := `{"typ":"JWT","alg":"UNKNOWN"}`
		claims := `{"sub":"user"}`
		signature := "signature"

		brokenToken := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
			base64.RawURLEncoding.EncodeToString([]byte(claims)) + "." + signature

		_, err := ParseUnverified(brokenToken)
		if err == nil {
			t.Error("ParseUnverified() should return error for unsupported algorithm")
		}
		if !strings.Contains(err.Error(), "unsupported") {
			t.Errorf("Error should mention unsupported, got: %v", err)
		}
	})
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
			_, err := ParseUnverified(tt.token)
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
	parsedToken, err := ParseUnverified(token)
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
	valid, err := VerifyJWT(parsedToken.Raw, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("VerifyJWT() error = %v", err)
	}

	if !valid {
		t.Error("VerifyJWT() returned false for valid token")
	}
}

func TestSignES256(t *testing.T) {
	privateKey, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	claims := jwt.MapClaims{
		"iss": "test-issuer",
		"sub": "user123",
		"exp": 9999999999,
	}

	token, err := SignES256(claims, privateKey)
	if err != nil {
		t.Fatalf("SignES256() error = %v", err)
	}

	if token == "" {
		t.Error("SignES256() returned empty token")
	}

	// Verify the token
	valid, err := VerifyJWT(token, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("VerifyJWT() error = %v", err)
	}

	if !valid {
		t.Error("SignES256() produced invalid token")
	}
}

func TestSignES384(t *testing.T) {
	privateKey, err := GenerateECDSAKeyP384()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP384() error = %v", err)
	}

	claims := jwt.MapClaims{
		"iss": "test-issuer",
		"sub": "user123",
		"exp": 9999999999,
	}

	token, err := SignES384(claims, privateKey)
	if err != nil {
		t.Fatalf("SignES384() error = %v", err)
	}

	if token == "" {
		t.Error("SignES384() returned empty token")
	}

	// Verify the token
	valid, err := VerifyJWT(token, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("VerifyJWT() error = %v", err)
	}

	if !valid {
		t.Error("SignES384() produced invalid token")
	}
}

func TestSignES512(t *testing.T) {
	privateKey, err := GenerateECDSAKeyP521()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP521() error = %v", err)
	}

	claims := jwt.MapClaims{
		"iss": "test-issuer",
		"sub": "user123",
		"exp": 9999999999,
	}

	token, err := SignES512(claims, privateKey)
	if err != nil {
		t.Fatalf("SignES512() error = %v", err)
	}

	if token == "" {
		t.Error("SignES512() returned empty token")
	}

	// Verify the token
	valid, err := VerifyJWT(token, &privateKey.PublicKey)
	if err != nil {
		t.Fatalf("VerifyJWT() error = %v", err)
	}

	if !valid {
		t.Error("SignES512() produced invalid token")
	}
}

func TestIsExpired(t *testing.T) {
	t.Run("Expired token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "test-issuer",
			"sub": "user123",
			"exp": float64(time.Now().Add(-1 * time.Hour).Unix()), // 已过期
		}

		token, _, err := GenerateES256(claims)
		if err != nil {
			t.Fatalf("GenerateES256() error = %v", err)
		}

		parsedToken, err := ParseUnverified(token)
		if err != nil {
			t.Fatalf("ParseUnverified() error = %v", err)
		}

		expired, err := IsExpired(parsedToken)
		if err != nil {
			t.Fatalf("IsExpired() error = %v", err)
		}

		if !expired {
			t.Error("IsExpired() returned false for expired token")
		}
	})

	t.Run("Valid token", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "test-issuer",
			"sub": "user123",
			"exp": float64(time.Now().Add(24 * time.Hour).Unix()), // 未过期
		}

		token, _, err := GenerateES256(claims)
		if err != nil {
			t.Fatalf("GenerateES256() error = %v", err)
		}

		parsedToken, err := ParseUnverified(token)
		if err != nil {
			t.Fatalf("ParseUnverified() error = %v", err)
		}

		expired, err := IsExpired(parsedToken)
		if err != nil {
			t.Fatalf("IsExpired() error = %v", err)
		}

		if expired {
			t.Error("IsExpired() returned true for valid token")
		}
	})

	t.Run("Token without expiration", func(t *testing.T) {
		claims := jwt.MapClaims{
			"iss": "test-issuer",
			"sub": "user123",
			// 没有 exp 字段
		}

		token, _, err := GenerateES256(claims)
		if err != nil {
			t.Fatalf("GenerateES256() error = %v", err)
		}

		parsedToken, err := ParseUnverified(token)
		if err != nil {
			t.Fatalf("ParseUnverified() error = %v", err)
		}

		expired, err := IsExpired(parsedToken)
		if err != nil {
			t.Fatalf("IsExpired() error = %v", err)
		}

		if expired {
			t.Error("IsExpired() returned true for token without expiration")
		}
	})
}

func TestTokenLengthValidation(t *testing.T) {
	t.Run("Empty token", func(t *testing.T) {
		_, err := ParseUnverified("")
		if err == nil {
			t.Error("ParseUnverified() should return error for empty token")
		}
	})

	t.Run("Oversized token", func(t *testing.T) {
		// Create a token larger than maxTokenLength (10KB)
		largeToken := strings.Repeat("a", 11*1024)
		_, err := ParseUnverified(largeToken + ".signature")
		if err == nil {
			t.Error("ParseUnverified() should return error for oversized token")
		}
	})
}
