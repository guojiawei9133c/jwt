package jwt

import (
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"strings"
	"time"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrTokenExpired     = errors.New("token expired")
	ErrInvalidKey       = errors.New("invalid key")
)

// SigningMethod 定义签名方法
type SigningMethod string

const (
	HS256 SigningMethod = "HS256" // HMAC SHA-256
	HS384 SigningMethod = "HS384" // HMAC SHA-384
	HS512 SigningMethod = "HS512" // HMAC SHA-512
	ES256 SigningMethod = "ES256" // ECDSA SHA-256
)

// Claims JWT 载荷声明
type Claims struct {
	Issuer   string                 `json:"iss,omitempty"`   // 签发者
	Subject  string                 `json:"sub,omitempty"`   // 主题
	Audience string                 `json:"aud,omitempty"`   // 接收方
	ExpireAt int64                  `json:"exp,omitempty"`   // 过期时间
	IssuedAt int64                  `json:"iat,omitempty"`   // 签发时间
	NotBefore int64                 `json:"nbf,omitempty"`   // 生效时间
	ID       string                 `json:"jti,omitempty"`   // JWT ID
	CustomData map[string]interface{} `json:"-"`              // 自定义数据
}

// Token 表示一个 JWT Token
type Token struct {
	Raw       string
	Header    map[string]interface{}
	Claims    *Claims
	Signature string
	Method    SigningMethod
}

// Generator JWT 生成器
type Generator struct {
	method SigningMethod
	secret []byte
	pubKey *ecdsa.PublicKey
	priKey *ecdsa.PrivateKey
}

// NewGenerator 创建 JWT 生成器 (HMAC)
func NewGenerator(method SigningMethod, secret []byte) (*Generator, error) {
	if len(secret) == 0 {
		return nil, ErrInvalidKey
	}
	return &Generator{
		method: method,
		secret: secret,
	}, nil
}

// NewGeneratorWithECDSA 创建 JWT 生成器 (ECDSA)
func NewGeneratorWithECDSA(method SigningMethod, priKey *ecdsa.PrivateKey) (*Generator, error) {
	if priKey == nil {
		return nil, ErrInvalidKey
	}
	return &Generator{
		method: method,
		priKey: priKey,
		pubKey: &priKey.PublicKey,
	}, nil
}

// SetPublicKey 设置公钥（用于验证）
func (g *Generator) SetPublicKey(pubKey *ecdsa.PublicKey) {
	g.pubKey = pubKey
}

// Decode 解析 JWT Token，不验证签名
// 用于两阶段验证：先解析获取签发者信息，再查找密钥验证
func Decode(tokenString string) (*Token, error) {
	if tokenString == "" {
		return nil, ErrInvalidToken
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// 解码 Header
	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var header map[string]interface{}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrInvalidToken
	}

	// 解码 Payload
	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, ErrInvalidToken
	}

	// 解析 Claims
	claims := &Claims{CustomData: make(map[string]interface{})}
	if v, ok := payload["iss"].(string); ok {
		claims.Issuer = v
	}
	if v, ok := payload["sub"].(string); ok {
		claims.Subject = v
	}
	if v, ok := payload["aud"].(string); ok {
		claims.Audience = v
	}
	if v, ok := payload["exp"].(float64); ok {
		claims.ExpireAt = int64(v)
	}
	if v, ok := payload["iat"].(float64); ok {
		claims.IssuedAt = int64(v)
	}
	if v, ok := payload["nbf"].(float64); ok {
		claims.NotBefore = int64(v)
	}
	if v, ok := payload["jti"].(string); ok {
		claims.ID = v
	}

	// 提取自定义数据
	for k, v := range payload {
		switch k {
		case "iss", "sub", "aud", "exp", "iat", "nbf", "jti":
			// 标准字段跳过
		default:
			claims.CustomData[k] = v
		}
	}

	// 获取签名方法
	method := SigningMethod("")
	if v, ok := header["alg"].(string); ok {
		method = SigningMethod(v)
	}

	return &Token{
		Raw:       tokenString,
		Header:    header,
		Claims:    claims,
		Signature: parts[2],
		Method:    method,
	}, nil
}

// Generate 生成 Token
func (g *Generator) Generate(claims *Claims) (string, error) {
	now := time.Now().Unix()

	if claims.IssuedAt == 0 {
		claims.IssuedAt = now
	}
	if claims.ExpireAt == 0 {
		claims.ExpireAt = now + 3600 // 默认1小时
	}

	header := map[string]interface{}{
		"typ": "JWT",
		"alg": string(g.method),
	}

	// 合并自定义数据
	payload := make(map[string]interface{})
	if claims.Issuer != "" {
		payload["iss"] = claims.Issuer
	}
	if claims.Subject != "" {
		payload["sub"] = claims.Subject
	}
	if claims.Audience != "" {
		payload["aud"] = claims.Audience
	}
	if claims.ExpireAt > 0 {
		payload["exp"] = claims.ExpireAt
	}
	if claims.IssuedAt > 0 {
		payload["iat"] = claims.IssuedAt
	}
	if claims.NotBefore > 0 {
		payload["nbf"] = claims.NotBefore
	}
	if claims.ID != "" {
		payload["jti"] = claims.ID
	}
	for k, v := range claims.CustomData {
		payload[k] = v
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)

	headerEncoded := base64URLEncode(headerJSON)
	payloadEncoded := base64URLEncode(payloadJSON)

	signingInput := headerEncoded + "." + payloadEncoded

	signature, err := g.sign(signingInput)
	if err != nil {
		return "", err
	}

	return signingInput + "." + signature, nil
}

// Verify 验证 Token
func (g *Generator) Verify(tokenString string) (*Claims, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// 验证签名
	if !g.verify(parts[0]+"."+parts[1], parts[2]) {
		return nil, ErrInvalidSignature
	}

	// 解码 payload
	payloadJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, ErrInvalidToken
	}

	claims := &Claims{CustomData: make(map[string]interface{})}

	if v, ok := payload["iss"].(string); ok {
		claims.Issuer = v
	}
	if v, ok := payload["sub"].(string); ok {
		claims.Subject = v
	}
	if v, ok := payload["aud"].(string); ok {
		claims.Audience = v
	}
	if v, ok := payload["exp"].(float64); ok {
		claims.ExpireAt = int64(v)
	}
	if v, ok := payload["iat"].(float64); ok {
		claims.IssuedAt = int64(v)
	}
	if v, ok := payload["nbf"].(float64); ok {
		claims.NotBefore = int64(v)
	}
	if v, ok := payload["jti"].(string); ok {
		claims.ID = v
	}

	// 提取自定义数据
	for k, v := range payload {
		switch k {
		case "iss", "sub", "aud", "exp", "iat", "nbf", "jti":
			// 标准字段跳过
		default:
			claims.CustomData[k] = v
		}
	}

	// 检查过期时间
	if claims.ExpireAt > 0 && time.Now().Unix() > claims.ExpireAt {
		return nil, ErrTokenExpired
	}

	// 检查生效时间
	if claims.NotBefore > 0 && time.Now().Unix() < claims.NotBefore {
		return nil, ErrTokenExpired
	}

	return claims, nil
}

// VerifyBearer 验证 Bearer Token
// authorization 格式: "Bearer <token>" 或直接传 token
func (g *Generator) VerifyBearer(authorization string) (*Claims, error) {
	if authorization == "" {
		return nil, ErrInvalidToken
	}

	// 去除 Bearer 前缀
	token := strings.TrimPrefix(authorization, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")
	token = strings.TrimPrefix(token, "BEARER ")

	// 去除前后空格
	token = strings.TrimSpace(token)

	if token == "" {
		return nil, ErrInvalidToken
	}

	return g.Verify(token)
}

// sign 签名
func (g *Generator) sign(signingInput string) (string, error) {
	var sig []byte

	switch g.method {
	case HS256, HS384, HS512:
		h := hmac.New(newHashFunc(g.method), g.secret)
		h.Write([]byte(signingInput))
		sig = h.Sum(nil)
	case ES256:
		h := sha256.New()
		h.Write([]byte(signingInput))
		hash := h.Sum(nil)
		r, s, err := ecdsa.Sign(rand.Reader, g.priKey, hash)
		if err != nil {
			return "", err
		}
		sig = append(r.Bytes(), s.Bytes()...)
	default:
		return "", fmt.Errorf("unsupported signing method: %s", g.method)
	}

	return base64URLEncode(sig), nil
}

// verify 验证签名
func (g *Generator) verify(signingInput, signature string) bool {
	sig, err := base64URLDecode(signature)
	if err != nil {
		return false
	}

	switch g.method {
	case HS256, HS384, HS512:
		h := hmac.New(newHashFunc(g.method), g.secret)
		h.Write([]byte(signingInput))
		expectedSig := h.Sum(nil)
		return hmac.Equal(sig, expectedSig)
	case ES256:
		h := sha256.New()
		h.Write([]byte(signingInput))
		hash := h.Sum(nil)
		if len(sig) < 64 {
			return false
		}
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:64])
		return ecdsa.Verify(g.pubKey, hash, r, s)
	default:
		return false
	}
}

func newHashFunc(method SigningMethod) func() hash.Hash {
	switch method {
	case HS256:
		return sha256.New
	case HS384:
		return sha512.New384
	case HS512:
		return sha512.New
	default:
		return sha256.New
	}
}

func base64URLEncode(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64URLDecode(data string) ([]byte, error) {
	switch len(data) % 4 {
	case 2:
		data += "=="
	case 3:
		data += "="
	}
	return base64.URLEncoding.DecodeString(data)
}
