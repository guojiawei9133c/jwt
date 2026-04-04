package jwt

import (
	"crypto/ecdsa"
	"strings"
	"testing"
)

func TestGenerateECDSAKeyP256(t *testing.T) {
	key, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	if key == nil {
		t.Fatal("GenerateECDSAKeyP256() returned nil key")
	}
}

func TestGenerateECDSAKeyP384(t *testing.T) {
	key, err := GenerateECDSAKeyP384()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP384() error = %v", err)
	}

	if key == nil {
		t.Fatal("GenerateECDSAKeyP384() returned nil key")
	}
}

func TestGenerateECDSAKeyP521(t *testing.T) {
	key, err := GenerateECDSAKeyP521()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP521() error = %v", err)
	}

	if key == nil {
		t.Fatal("GenerateECDSAKeyP521() returned nil key")
	}
}

func TestPrivateKeyToBytes(t *testing.T) {
	key, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	bytes, err := PrivateKeyToBytes(key)
	if err != nil {
		t.Fatalf("PrivateKeyToBytes() error = %v", err)
	}

	if len(bytes) == 0 {
		t.Error("PrivateKeyToBytes() returned empty bytes")
	}
}

func TestBytesToPrivateKey(t *testing.T) {
	key1, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	// 先转换为字节
	bytes1, err := PrivateKeyToBytes(key1)
	if err != nil {
		t.Fatalf("PrivateKeyToBytes() error = %v", err)
	}

	// 再从字节恢复
	key2, err := BytesToPrivateKey(bytes1)
	if err != nil {
		t.Fatalf("BytesToPrivateKey() error = %v", err)
	}

	if key2 == nil {
		t.Fatal("BytesToPrivateKey() returned nil key")
	}

	// 验证往返：再转换一次字节应该相同
	bytes2, err := PrivateKeyToBytes(key2)
	if err != nil {
		t.Fatalf("PrivateKeyToBytes() second call error = %v", err)
	}

	// 比较序列化后的字节
	if string(bytes1) != string(bytes2) {
		t.Error("BytesToPrivateKey() round trip produced different bytes")
	}
}

func TestPrivateKeyToPEM(t *testing.T) {
	key, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	pemBytes, err := PrivateKeyToPEM(key)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM() error = %v", err)
	}

	if len(pemBytes) == 0 {
		t.Error("PrivateKeyToPEM() returned empty PEM")
	}

	pemStr := string(pemBytes)
	if !strings.Contains(pemStr, "-----BEGIN EC PRIVATE KEY-----") {
		t.Error("PrivateKeyToPEM() missing EC PRIVATE KEY header")
	}

	if !strings.Contains(pemStr, "-----END EC PRIVATE KEY-----") {
		t.Error("PrivateKeyToPEM() missing EC PRIVATE KEY footer")
	}
}

func TestPEMToPrivateKey(t *testing.T) {
	key1, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	// 先转换为 PEM
	pemBytes1, err := PrivateKeyToPEM(key1)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM() error = %v", err)
	}

	// 再从 PEM 恢复
	key2, err := PEMToPrivateKey(pemBytes1)
	if err != nil {
		t.Fatalf("PEMToPrivateKey() error = %v", err)
	}

	if key2 == nil {
		t.Fatal("PEMToPrivateKey() returned nil key")
	}

	// 验证往返：再转换一次 PEM 应该相同
	pemBytes2, err := PrivateKeyToPEM(key2)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM() second call error = %v", err)
	}

	if string(pemBytes1) != string(pemBytes2) {
		t.Error("PEMToPrivateKey() round trip produced different PEM")
	}
}

func TestKeyRoundTrip(t *testing.T) {
	// 生成原始密钥
	originalKey, err := GenerateECDSAKeyP256()
	if err != nil {
		t.Fatalf("GenerateECDSAKeyP256() error = %v", err)
	}

	// 转换为 PEM
	pemBytes, err := PrivateKeyToPEM(originalKey)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM() error = %v", err)
	}

	// 从 PEM 解析
	parsedKey, err := PEMToPrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("PEMToPrivateKey() error = %v", err)
	}

	// 再次转换为 PEM
	pemBytes2, err := PrivateKeyToPEM(parsedKey)
	if err != nil {
		t.Fatalf("PrivateKeyToPEM() second call error = %v", err)
	}

	// 两次 PEM 应该完全相同
	if string(pemBytes) != string(pemBytes2) {
		t.Error("Round trip produced different PEM output")
	}
}

func TestPEMToPrivateKeyInvalidPEM(t *testing.T) {
	tests := []struct {
		name     string
		pemData  string
		wantErr  bool
		errContains string
	}{
		{
			name:     "Not PEM format",
			pemData:  "not a pem file",
			wantErr:  true,
			errContains: "failed to decode",
		},
		{
			name:     "Wrong type",
			pemData:  "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAyGW==\n-----END RSA PRIVATE KEY-----",
			wantErr:  true,
			errContains: "failed to decode",
		},
		{
			name:     "Empty",
			pemData:  "",
			wantErr:  true,
			errContains: "failed to decode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := PEMToPrivateKey([]byte(tt.pemData))
			if tt.wantErr && err == nil {
				t.Error("PEMToPrivateKey() should return error")
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("Error should contain %q, got: %v", tt.errContains, err)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("PEMToPrivateKey() unexpected error: %v", err)
			}
		})
	}
}

func TestGenerateMultipleKeys(t *testing.T) {
	// 测试多次生成密钥，确保密钥是唯一的
	keys := make(map[string]bool)

	for i := 0; i < 10; i++ {
		key, err := GenerateECDSAKeyP256()
		if err != nil {
			t.Fatalf("GenerateECDSAKeyP256() iteration %d error = %v", i, err)
		}

		// 将密钥序列化为字节作为唯一标识
		keyBytes, err := PrivateKeyToBytes(key)
		if err != nil {
			t.Fatalf("PrivateKeyToBytes() error = %v", err)
		}

		keyStr := string(keyBytes)
		if keys[keyStr] {
			t.Errorf("Generated duplicate key at iteration %d", i)
		}
		keys[keyStr] = true
	}

	if len(keys) != 10 {
		t.Errorf("Generated %d unique keys, want 10", len(keys))
	}
}

func TestGenerateAllCurves(t *testing.T) {
	tests := []struct {
		name    string
		genFunc func() (*ecdsa.PrivateKey, error)
	}{
		{"P256", GenerateECDSAKeyP256},
		{"P384", GenerateECDSAKeyP384},
		{"P521", GenerateECDSAKeyP521},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := tt.genFunc()
			if err != nil {
				t.Fatalf("%s() error = %v", tt.name, err)
			}

			if key == nil {
				t.Errorf("%s() returned nil key", tt.name)
			}

			// 验证可以转换为 PEM 并恢复
			pemBytes1, err := PrivateKeyToPEM(key)
			if err != nil {
				t.Fatalf("PrivateKeyToPEM() error = %v", err)
			}

			restoredKey, err := PEMToPrivateKey(pemBytes1)
			if err != nil {
				t.Fatalf("PEMToPrivateKey() error = %v", err)
			}

			// 验证往返：再转换一次 PEM 应该相同
			pemBytes2, err := PrivateKeyToPEM(restoredKey)
			if err != nil {
				t.Fatalf("PrivateKeyToPEM() second call error = %v", err)
			}

			if string(pemBytes1) != string(pemBytes2) {
				t.Errorf("%s() round trip failed", tt.name)
			}
		})
	}
}
