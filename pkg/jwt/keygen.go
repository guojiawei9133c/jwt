package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// GenerateHMACKey256 生成 256 位 HMAC 密钥 (用于 HS256)
func GenerateHMACKey256() ([]byte, error) {
	return generateHMACKey(32)
}

// GenerateHMACKey384 生成 384 位 HMAC 密钥 (用于 HS384)
func GenerateHMACKey384() ([]byte, error) {
	return generateHMACKey(48)
}

// GenerateHMACKey512 生成 512 位 HMAC 密钥 (用于 HS512)
func GenerateHMACKey512() ([]byte, error) {
	return generateHMACKey(64)
}

func generateHMACKey(bytes int) ([]byte, error) {
	key := make([]byte, bytes)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}
	return key, nil
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
