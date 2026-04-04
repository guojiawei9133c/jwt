package jwt

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// ParseUnverified 解析 JWT token 但不验证签名
// 性能最佳，适用于需要先读取 claims 信息再决定如何验证的场景
// 返回解析后的 token 对象、原始 token 字符串和可能的错误
//
// 注意：此方法不验证签名，请勿直接信任解析出的 claims
// 典型用法：
//   token, raw, _ := jwt.ParseUnverified(tokenString)
//   // 根据 token.Claims 获取信息，例如 issuer
//   issuer := token.Claims.(jwt.MapClaims)["iss"]
//   // 然后使用对应的密钥验证签名
func ParseUnverified(tokenString string) (*jwt.Token, string, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, "", fmt.Errorf("token contains an invalid number of segments")
	}

	// 解码 header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode header: %w", err)
	}

	// 解码 claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, "", fmt.Errorf("failed to decode claims: %w", err)
	}

	// 解析 claims
	var claims jwt.MapClaims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, "", fmt.Errorf("failed to parse claims: %w", err)
	}

	// 创建 Token 对象（不验证签名）
	token := &jwt.Token{
		Raw:       tokenString,
		Method:    jwt.GetSigningMethod(jwt.SigningMethodES256.Alg()),
		Header:    nil,
		Claims:    claims,
		Signature: []byte(parts[2]),
	}

	// 解析 header
	if err := json.Unmarshal(headerJSON, &token.Header); err != nil {
		return nil, "", fmt.Errorf("failed to parse header: %w", err)
	}

	return token, tokenString, nil
}

func VerifyJWT(
	tokenString string,
	publicKey *ecdsa.PublicKey,
) (bool, error) {
	// 使用jwt.Parse验证token，不解析claims（因为我们只需要验证签名）
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// 验证签名算法
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return false, err
	}

	return token.Valid, nil
}

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
