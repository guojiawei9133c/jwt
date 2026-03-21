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
	ErrMarshal          = errors.New("failed to marshal claims")
)

const (
	defaultExpirationSeconds = 3600 // 默认1小时
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

// GenerateWithKey 生成带有独立密钥的 JWT token
// 自动生成新的随机密钥，存储到 KeyStore，并生成 token
// 返回 token 字符串，不返回密钥（密钥由 KeyStore 管理）
func GenerateWithKey(store KeyStore, gen *Generator, claims *Claims, keySize func() ([]byte, error)) (string, error) {
	if claims.ID == "" {
		return "", ErrInvalidKey
	}

	// 生成新的随机密钥
	secret, err := keySize()
	if err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}

	// 存储到 KeyStore
	store.Set(claims.ID, secret)

	// 创建使用新密钥的 Generator
	newGen, err := NewGenerator(gen.method, secret)
	if err != nil {
		return "", err
	}

	// 生成 token
	return newGen.Generate(claims)
}

// GenerateWithKeyAndTTL 生成带有独立密钥和过期时间的 JWT token
// 密钥会在指定时间后自动过期
func GenerateWithKeyAndTTL(store KeyStore, gen *Generator, claims *Claims, keySize func() ([]byte, error), ttl time.Duration) (string, error) {
	if claims.ID == "" {
		return "", ErrInvalidKey
	}

	// 生成新的随机密钥
	secret, err := keySize()
	if err != nil {
		return "", fmt.Errorf("failed to generate key: %w", err)
	}

	// 存储到 KeyStore，带 TTL
	store.SetWithTTL(claims.ID, secret, ttl)

	// 创建使用新密钥的 Generator
	newGen, err := NewGenerator(gen.method, secret)
	if err != nil {
		return "", err
	}

	// 生成 token
	return newGen.Generate(claims)
}

// VerifyWithKeyStore 使用 KeyStore 验证 token
// 自动从 KeyStore 根据 jti 查找密钥并验证
// 注意: 当前仅支持 HMAC 算法 (HS256/HS384/HS512)
func VerifyWithKeyStore(tokenString string, store KeyStore) (*Claims, error) {
	// 解码 token 获取 jti
	token, err := Decode(tokenString)
	if err != nil {
		return nil, err
	}

	if token.Claims.ID == "" {
		return nil, ErrInvalidKey
	}

	// 验证算法类型：KeyStore 仅支持 HMAC
	if token.Method != HS256 && token.Method != HS384 && token.Method != HS512 {
		return nil, fmt.Errorf("KeyStore only supports HMAC algorithms, got: %s", token.Method)
	}

	// 从 KeyStore 获取密钥
	secret, ok := store.Get(token.Claims.ID)
	if !ok {
		return nil, ErrInvalidKey
	}

	// 创建 Generator 并验证
	gen, err := NewGenerator(token.Method, secret)
	if err != nil {
		return nil, err
	}

	return gen.Verify(tokenString)
}

// Generate 生成 Token
func (g *Generator) Generate(claims *Claims) (string, error) {
	now := time.Now().Unix()

	// 使用局部变量，不修改输入参数
	issuedAt := claims.IssuedAt
	if issuedAt == 0 {
		issuedAt = now
	}

	expireAt := claims.ExpireAt
	if expireAt == 0 {
		expireAt = now + defaultExpirationSeconds
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
	if expireAt > 0 {
		payload["exp"] = expireAt
	}
	if issuedAt > 0 {
		payload["iat"] = issuedAt
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

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMarshal, err)
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrMarshal, err)
	}

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
	// 使用局部变量避免修改输入
	padded := data
	switch len(padded) % 4 {
	case 2:
		padded += "=="
	case 3:
		padded += "="
	}
	return base64.URLEncoding.DecodeString(padded)
}
