package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// GenerateECDSAKeyP256 生成 P256 曲线 ECDSA 私钥 (用于 ES256)
func GenerateECDSAKeyP256() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	return privateKey, nil
}

// GenerateECDSAKeyP384 生成 P384 曲线 ECDSA 私钥 (用于 ES384)
func GenerateECDSAKeyP384() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	return privateKey, nil
}

// GenerateECDSAKeyP521 生成 P521 曲线 ECDSA 私钥 (用于 ES521)
func GenerateECDSAKeyP521() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}
	return privateKey, nil
}

// PublicKeyToBytes 将 ECDSA 公钥转换为字节
func PublicKeyToBytes(publicKey *ecdsa.PublicKey) ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	return bytes, nil
}

// BytesToPublicKey 将字节转换为 ECDSA 公钥
func BytesToPublicKey(bytes []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return publicKey, nil
}

// PublicKeyToPEM 将 ECDSA 公钥转换为 PEM 格式
func PublicKeyToPEM(publicKey *ecdsa.PublicKey) ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: bytes,
	}

	pemBytes := pem.EncodeToMemory(pemBlock)
	return pemBytes, nil
}

// PEMToPublicKey 将 PEM 格式转换为 ECDSA 公钥
func PEMToPublicKey(pemBytes []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("invalid PEM block type: %s", block.Type)
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return publicKey, nil
}

func PrivateKeyToBytes(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	bytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	return bytes, nil
}

func BytesToPrivateKey(bytes []byte) (*ecdsa.PrivateKey, error) {
	privateKey, err := x509.ParseECPrivateKey(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return privateKey, nil
}

func PrivateKeyToPEM(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// 将ECDSA私钥转换为ASN.1 DER格式
	derBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	// 创建PEM块
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY", // PEM类型标识
		Bytes: derBytes,         // DER编码的私钥数据
	}

	// 将PEM块编码为字节
	pemBytes := pem.EncodeToMemory(pemBlock)

	return pemBytes, nil
}

func PEMToPrivateKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	// 解码PEM数据
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// 检查PEM块类型
	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("invalid PEM block type: %s", block.Type)
	}

	// 解析ECDSA私钥
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}

	return privateKey, nil
}
