package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// GenerateHMACKey 生成随机 HMAC 密钥
// bits: 密钥长度（位），建议 256/384/512 对应 HS256/HS384/HS512
// 返回十六进制字符串形式的密钥
func GenerateHMACKey(bits int) (string, error) {
	if bits <= 0 {
		return "", errors.New("invalid key size")
	}

	bytes := bits / 8
	if bits%8 != 0 {
		bytes++
	}

	key := make([]byte, bytes)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}

	return hex.EncodeToString(key), nil
}

// GenerateHMACKeyBase64 生成随机 HMAC 密钥（Base64 编码）
func GenerateHMACKeyBase64(bits int) (string, error) {
	if bits <= 0 {
		return "", errors.New("invalid key size")
	}

	bytes := bits / 8
	if bits%8 != 0 {
		bytes++
	}

	key := make([]byte, bytes)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("failed to generate random key: %w", err)
	}

	// 使用标准 Base64（不是 URL Safe），便于用户使用
	return encodeBase64(key), nil
}

// ECDSAKeyPair ECDSA 密钥对
type ECDSAKeyPair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
}

// GenerateECDSAKeyPair 生成 ECDSA 密钥对
// curve: 椭圆曲线类型，支持 "P256", "P384", "P521"
func GenerateECDSAKeyPair(curve string) (*ECDSAKeyPair, error) {
	var c elliptic.Curve

	switch strings.ToUpper(curve) {
	case "P256":
		c = elliptic.P256()
	case "P384":
		c = elliptic.P384()
	case "P521":
		c = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s (supported: P256, P384, P521)", curve)
	}

	privateKey, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}

	return &ECDSAKeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
	}, nil
}

// PrivateKeyPEM 将私钥编码为 PEM 格式
func (kp *ECDSAKeyPair) PrivateKeyPEM() (string, error) {
	if kp.PrivateKey == nil {
		return "", errors.New("private key is nil")
	}

	derBytes, err := x509.MarshalECPrivateKey(kp.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// PublicKeyPEM 将公钥编码为 PEM 格式
func (kp *ECDSAKeyPair) PublicKeyPEM() (string, error) {
	if kp.PublicKey == nil {
		return "", errors.New("public key is nil")
	}

	derBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	}

	return string(pem.EncodeToMemory(block)), nil
}

// ParseECDSAFromPEM 从 PEM 格式解析 ECDSA 私钥
func ParseECDSAFromPEM(pemData []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("expected EC PRIVATE KEY, got %s", block.Type)
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}

	return key, nil
}

// ParsePublicKeyFromPEM 从 PEM 格式解析公钥
func ParsePublicKeyFromPEM(pemData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("expected PUBLIC KEY, got %s", block.Type)
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return ecdsaKey, nil
}

func encodeBase64(data []byte) string {
	return strings.TrimRight(encodeBase64Std(data), "=")
}

func encodeBase64Std(data []byte) string {
	const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	n := len(data)
	output := make([]byte, 0, (n*8+5)/6)

	for i := 0; i < n; i += 3 {
		var val uint32

		switch {
		case i+2 < n:
			val = uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
			output = append(output,
				base64Chars[val>>18],
				base64Chars[(val>>12)&63],
				base64Chars[(val>>6)&63],
				base64Chars[val&63],
			)
		case i+1 < n:
			val = uint32(data[i])<<16 | uint32(data[i+1])<<8
			output = append(output,
				base64Chars[val>>18],
				base64Chars[(val>>12)&63],
				base64Chars[(val>>6)&63],
			)
		default:
			val = uint32(data[i]) << 16
			output = append(output,
				base64Chars[val>>18],
				base64Chars[(val>>12)&63],
			)
		}
	}

	return string(output)
}
