package jwt

import (
	"strings"
	"testing"
)

func TestExtractBearerToken_Valid(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		wantToken     string
		wantErr       bool
	}{
		{
			name:          "Standard Bearer token",
			authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantErr:       false,
		},
		{
			name:          "Lowercase bearer",
			authorization: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantErr:       false,
		},
		{
			name:          "Uppercase BEARER",
			authorization: "BEARER eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantErr:       false,
		},
		{
			name:          "Mixed case BeArEr",
			authorization: "BeArEr eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantErr:       false,
		},
		{
			name:          "Multiple spaces after Bearer",
			authorization: "Bearer   eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantErr:       false,
		},
		{
			name:          "Trailing spaces",
			authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  ",
			wantToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantErr:       false,
		},
		{
			name:          "Leading spaces (invalid)",
			authorization: "  Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantToken:     "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractBearerToken(tt.authorization)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && token != tt.wantToken {
				t.Errorf("ExtractBearerToken() = %v, want %v", token, tt.wantToken)
			}
		})
	}
}

func TestExtractBearerToken_Errors(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		wantErr       bool
		errContains   string
	}{
		{
			name:          "Empty string",
			authorization: "",
			wantErr:       true,
			errContains:   "empty",
		},
		{
			name:          "Only Bearer",
			authorization: "Bearer",
			wantErr:       true,
			errContains:   "format",
		},
		{
			name:          "Bearer with space only",
			authorization: "Bearer ",
			wantErr:       true,
			errContains:   "empty",
		},
		{
			name:          "Bearer with whitespace only",
			authorization: "Bearer   ",
			wantErr:       true,
			errContains:   "empty",
		},
		{
			name:          "No Bearer prefix",
			authorization: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantErr:       true,
			errContains:   "format",
		},
		{
			name:          "Basic auth instead of Bearer",
			authorization: "Basic dXNlcm5hbWU6cGFzc3dvcmQ=",
			wantErr:       true,
			errContains:   "format",
		},
		{
			name:          "Digest auth",
			authorization: "Digest username=\"user\"",
			wantErr:       true,
			errContains:   "format",
		},
		{
			name:          "Token with invalid prefix",
			authorization: "Token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantErr:       true,
			errContains:   "format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractBearerToken(tt.authorization)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tt.errContains)) {
				t.Errorf("ExtractBearerToken() error = %v, should contain %v", err, tt.errContains)
			}
			if !tt.wantErr && token == "" {
				t.Error("ExtractBearerToken() returned empty token without error")
			}
		})
	}
}

func TestExtractBearerToken_SpecialCharacters(t *testing.T) {
	// Test with real JWT characters (URL-safe Base64)
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	tests := []struct {
		name          string
		authorization string
		wantToken     string
		wantErr       bool
	}{
		{
			name:          "Full JWT with dots",
			authorization: "Bearer " + token,
			wantToken:     token,
			wantErr:       false,
		},
		{
			name:          "JWT with underscore",
			authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.key_with_underscore",
			wantToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.key_with_underscore",
			wantErr:       false,
		},
		{
			name:          "JWT with hyphen",
			authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.key-with-hyphen",
			wantToken:     "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.key-with-hyphen",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractBearerToken(tt.authorization)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && token != tt.wantToken {
				t.Errorf("ExtractBearerToken() = %v, want %v", token, tt.wantToken)
			}
		})
	}
}

func TestExtractBearerToken_LongTokens(t *testing.T) {
	// Generate a very long token (simulating large payloads)
	longToken := strings.Repeat("a", 4096) + "." + strings.Repeat("b", 4096) + "." + strings.Repeat("c", 4096)
	authorization := "Bearer " + longToken

	token, err := ExtractBearerToken(authorization)
	if err != nil {
		t.Fatalf("ExtractBearerToken() error = %v", err)
	}
	if token != longToken {
		t.Errorf("ExtractBearerToken() token length = %d, want %d", len(token), len(longToken))
	}
}

func TestExtractBearerToken_TabAndNewline(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		wantToken     string
		wantErr       bool
	}{
		{
			name:          "Tab after Bearer",
			authorization: "Bearer\teyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantToken:     "",
			wantErr:       true, // SplitN with " " doesn't split on tab
		},
		{
			name:          "Newline after Bearer",
			authorization: "Bearer\neyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			wantToken:     "",
			wantErr:       true, // SplitN with " " doesn't split on newline
		},
		{
			name:          "Tab in token (should be preserved)",
			authorization: "Bearer eyJhbGci\ttest",
			wantToken:     "eyJhbGci\ttest",
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractBearerToken(tt.authorization)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && token != tt.wantToken {
				t.Errorf("ExtractBearerToken() = %v, want %v", token, tt.wantToken)
			}
		})
	}
}
