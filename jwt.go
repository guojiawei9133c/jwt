package jwt

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwtSegments   = 3                 // JWT token 由三部分组成: header.payload.signature
	maxTokenLength = 10 * 1024       // 最大 token 长度 10KB，防止 DoS 攻击
)

// ParseUnverified 解析 JWT token 但不验证签名
//
// 性能最佳，适用于需要先读取 claims 信息再决定如何验证的场景（如多租户系统）。
// 此方法直接解码 JWT 的各个部分，不进行签名验证，因此速度最快。
//
// ⚠️ 安全警告：此方法不验证签名，返回的 claims 不可直接信任！
// 必须后续使用 VerifyJWT() 或其他验证方法确认 token 签名有效。
//
// 参数：
//   tokenString - JWT 字符串
//
// 返回：
//   *jwt.Token - 解析后的 token 对象，可通过 token.Claims 访问声明
//   error - 解析失败时返回错误
//
// 典型用法（两阶段验证）：
//
//	token, _ := jwt.ParseUnverified(tokenString)
//	// 阶段1：从 claims 获取信息用于查找密钥
//	issuer := token.Claims.(jwt.MapClaims)["iss"]
//	publicKey := keyStore.Lookup(issuer)
//	// 阶段2：使用查找到的公钥验证签名
//	valid, _ := jwt.VerifyJWT(token.Raw, publicKey)
func ParseUnverified(tokenString string) (*jwt.Token, error) {
	// 验证 token 长度，防止 DoS 攻击
	if len(tokenString) > maxTokenLength {
		return nil, fmt.Errorf("token too large (max %d bytes)", maxTokenLength)
	}

	// 验证 token 长度，防止空 token
	if len(tokenString) == 0 {
		return nil, fmt.Errorf("token is empty")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != jwtSegments {
		return nil, fmt.Errorf("token contains an invalid number of segments, got %d, want %d", len(parts), jwtSegments)
	}

	// 解码 header (第0部分: base64(header))
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	// 解码 claims (第1部分: base64(claims))
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode claims: %w", err)
	}

	// 解析 claims 为 MapClaims
	var claims jwt.MapClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	// 解析 header 获取签名算法
	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	// 从 header 提取签名算法 (alg 字段)
	alg, ok := header["alg"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid alg field in header")
	}

	// 根据算法获取对应的签名方法
	method := jwt.GetSigningMethod(alg)
	if method == nil {
		return nil, fmt.Errorf("unsupported signing algorithm: %s", alg)
	}

	// 构造 Token 对象（不验证签名）
	token := &jwt.Token{
		Raw:       tokenString,                     // 原始 token 字符串
		Method:    method,                          // 签名方法
		Header:    header,                          // 解码后的 header
		Claims:    claims,                          // 解码后的 claims
		Signature: []byte(parts[2]),                // 签名部分（未验证）
	}

	return token, nil
}

// VerifyJWT 验证 JWT token 的签名
//
// 使用 ECDSA 公钥验证 token 签名的有效性。
// 只验证签名，不返回 claims 内容。如果需要获取 claims，请使用 ParseUnverified 先解析。
//
// 参数：
//   tokenString - JWT 字符串
//   publicKey - ECDSA 公钥，用于验证签名
//
// 返回：
//   bool - true 表示签名有效，false 表示签名无效
//   error - 验证过程中的错误（如格式错误、算法不匹配等）
//
// 注意：
//   - 此方法仅支持 ECDSA 签名算法 (ES256/ES384/ES512)
//   - 如果 token 使用了其他算法，将返回错误
func VerifyJWT(
	tokenString string,
	publicKey *ecdsa.PublicKey,
) (bool, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法是否为 ECDSA
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: only ECDSA is supported")
		}
		return publicKey, nil
	})

	if err != nil {
		return false, err
	}

	return token.Valid, nil
}

// IsExpired 检查 token 是否已过期
//
// 从 token 的 claims 中提取过期时间并检查是否已过期。
// 如果 token 没有设置过期时间 (exp claim)，则认为不会过期。
//
// 参数：
//   token - 已解析的 JWT token 对象
//
// 返回：
//   bool - true 表示已过期，false 表示未过期或没有设置过期时间
//   error - 解析失败时返回错误
func IsExpired(token *jwt.Token) (bool, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return false, fmt.Errorf("invalid claims type")
	}

	// 检查是否存在过期时间
	exp, ok := claims["exp"].(float64)
	if !ok {
		// 没有设置过期时间，认为不会过期
		return false, nil
	}

	// 检查是否已过期（使用当前时间）
	return int64(exp) < time.Now().Unix(), nil
}

// GenerateES256 生成使用 ES256 算法 (ECDSA P-256 + SHA-256) 签名的 JWT token
//
// 自动生成 P-256 曲线的 ECDSA 密钥对，并使用私钥对 claims 进行签名。
// 返回签名字符串和私钥，私钥应妥善保管用于后续验证。
//
// 参数：
//   claims - JWT 声明，可以是任何实现 jwt.Claims 接口的类型
//
// 返回：
//   string - 签名后的 JWT token 字符串
//   *ecdsa.PrivateKey - 生成的 ECDSA 私钥
//   error - 生成或签名失败时返回错误
//
// 注意：
//   - 私钥必须安全存储，泄露后攻击者可伪造任意 token
//   - 公钥可通过 privateKey.PublicKey 获取并用于验证
func GenerateES256[T jwt.Claims](
	claims T,
) (string, *ecdsa.PrivateKey, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	privateKey, err := GenerateECDSAKeyP256()
	if err != nil {
		return "", nil, err
	}

	result, err := token.SignedString(privateKey)
	if err != nil {
		return "", nil, err
	}

	return result, privateKey, nil
}

// SignES256 使用现有的 ES256 私钥对 claims 进行签名
//
// 使用提供的 P-256 ECDSA 私钥对 claims 进行签名，返回 JWT token 字符串。
// 与 GenerateES256 不同，此函数使用你提供的密钥而不是生成新密钥。
//
// 参数：
//   claims - JWT 声明，可以是任何实现 jwt.Claims 接口的类型
//   privateKey - 你自己的 P-256 ECDSA 私钥
//
// 返回：
//   string - 签名后的 JWT token 字符串
//   error - 签名失败时返回错误
//
// 注意：
//   - 你需要自己管理和保护私钥
//   - 公钥可通过 privateKey.PublicKey 获取并用于验证
func SignES256[T jwt.Claims](
	claims T,
	privateKey *ecdsa.PrivateKey,
) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	result, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return result, nil
}

// SignES384 使用现有的 ES384 私钥对 claims 进行签名
//
// 使用提供的 P-384 ECDSA 私钥对 claims 进行签名，返回 JWT token 字符串。
//
// 参数：
//   claims - JWT 声明，可以是任何实现 jwt.Claims 接口的类型
//   privateKey - 你自己的 P-384 ECDSA 私钥
//
// 返回：
//   string - 签名后的 JWT token 字符串
//   error - 签名失败时返回错误
func SignES384[T jwt.Claims](
	claims T,
	privateKey *ecdsa.PrivateKey,
) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodES384, claims)
	result, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return result, nil
}

// SignES512 使用现有的 ES512 私钥对 claims 进行签名
//
// 使用提供的 P-521 ECDSA 私钥对 claims 进行签名，返回 JWT token 字符串。
//
// 参数：
//   claims - JWT 声明，可以是任何实现 jwt.Claims 接口的类型
//   privateKey - 你自己的 P-521 ECDSA 私钥
//
// 返回：
//   string - 签名后的 JWT token 字符串
//   error - 签名失败时返回错误
func SignES512[T jwt.Claims](
	claims T,
	privateKey *ecdsa.PrivateKey,
) (string, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)
	result, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return result, nil
}

// GenerateES384 生成使用 ES384 算法 (ECDSA P-384 + SHA-384) 签名的 JWT token
//
// 自动生成 P-384 曲线的 ECDSA 密钥对，并使用私钥对 claims 进行签名。
// 返回签名字符串和私钥，私钥应妥善保管用于后续验证。
//
// 参数：
//   claims - JWT 声明，可以是任何实现 jwt.Claims 接口的类型
//
// 返回：
//   string - 签名后的 JWT token 字符串
//   *ecdsa.PrivateKey - 生成的 ECDSA 私钥
//   error - 生成或签名失败时返回错误
//
// 注意：
//   - 私钥必须安全存储，泄露后攻击者可伪造任意 token
//   - 公钥可通过 privateKey.PublicKey 获取并用于验证
func GenerateES384[T jwt.Claims](
	claims T,
) (string, *ecdsa.PrivateKey, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodES384, claims)

	privateKey, err := GenerateECDSAKeyP384()
	if err != nil {
		return "", nil, err
	}

	result, err := token.SignedString(privateKey)
	if err != nil {
		return "", nil, err
	}

	return result, privateKey, nil
}

// GenerateES512 生成使用 ES512 算法 (ECDSA P-521 + SHA-512) 签名的 JWT token
//
// 自动生成 P-521 曲线的 ECDSA 密钥对，并使用私钥对 claims 进行签名。
// 返回签名字符串和私钥，私钥应妥善保管用于后续验证。
//
// 参数：
//   claims - JWT 声明，可以是任何实现 jwt.Claims 接口的类型
//
// 返回：
//   string - 签名后的 JWT token 字符串
//   *ecdsa.PrivateKey - 生成的 ECDSA 私钥
//   error - 生成或签名失败时返回错误
//
// 注意：
//   - 私钥必须安全存储，泄露后攻击者可伪造任意 token
//   - 公钥可通过 privateKey.PublicKey 获取并用于验证
func GenerateES512[T jwt.Claims](
	claims T,
) (string, *ecdsa.PrivateKey, error) {

	token := jwt.NewWithClaims(jwt.SigningMethodES512, claims)

	privateKey, err := GenerateECDSAKeyP521()
	if err != nil {
		return "", nil, err
	}

	result, err := token.SignedString(privateKey)
	if err != nil {
		return "", nil, err
	}

	return result, privateKey, nil
}
