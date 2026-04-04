package jwt

import (
	"fmt"
	"strings"
)

// ExtractBearerToken 从 Authorization 头提取 JWT 字符串
// 格式: "Bearer <token>"
func ExtractBearerToken(authorization string) (string, error) {
	if authorization == "" {
		return "", fmt.Errorf("authorization header is empty")
	}

	// 按空格分割，最多分成2部分
	parts := strings.SplitN(authorization, " ", 2)

	// 检查格式是否正确
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("invalid authorization format, expected 'Bearer <token>'")
	}

	// 提取 tokenString 并去除首尾空格
	tokenString := strings.TrimSpace(parts[1])

	if tokenString == "" {
		return "", fmt.Errorf("token is empty")
	}

	return tokenString, nil
}
