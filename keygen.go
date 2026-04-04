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
