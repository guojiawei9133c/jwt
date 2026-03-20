package main

import (
	"fmt"
	"log"
	"time"

	"github.com/guojiawei9133c/jwt/pkg/jwt"
)

func main() {
	fmt.Println("=== JWT Library Demo ===")
	fmt.Println()

	// HMAC 示例
	hmacExample()

	// ECDSA 示例
	ecdsaExample()
}

func hmacExample() {
	fmt.Println("--- HMAC Signing (HS256) ---")

	// Generate a secure HMAC key
	secret, err := jwt.GenerateHMACKey256()
	if err != nil {
		log.Fatal(err)
	}

	gen, err := jwt.NewGenerator(jwt.HS256, secret)
	if err != nil {
		log.Fatal(err)
	}

	claims := &jwt.Claims{
		Issuer:   "my-app",
		Subject:  "user123",
		Audience: "my-api",
		ExpireAt: time.Now().Add(24 * time.Hour).Unix(),
		CustomData: map[string]interface{}{
			"role":   "admin",
			"name":   "John Doe",
			"email":  "john@example.com",
			"userId": 12345,
		},
	}

	token, err := gen.Generate(claims)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated Token:\n%s\n\n", token)

	verified, err := gen.Verify(token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Verified Claims:\n")
	fmt.Printf("  Issuer: %s\n", verified.Issuer)
	fmt.Printf("  Subject: %s\n", verified.Subject)
	fmt.Printf("  Audience: %s\n", verified.Audience)
	fmt.Printf("  ExpireAt: %s\n", time.Unix(verified.ExpireAt, 0).Format(time.RFC3339))
	fmt.Printf("  Custom Data: %+v\n\n", verified.CustomData)
}

func ecdsaExample() {
	fmt.Println("--- ECDSA Signing (ES256) ---")

	// Generate ECDSA key
	priKey, err := jwt.GenerateECDSAKeyP256()
	if err != nil {
		log.Fatal(err)
	}

	gen, err := jwt.NewGeneratorWithECDSA(jwt.ES256, priKey)
	if err != nil {
		log.Fatal(err)
	}
	gen.SetPublicKey(&priKey.PublicKey)

	claims := &jwt.Claims{
		Issuer:   "my-app",
		Subject:  "user456",
		ExpireAt: time.Now().Add(1 * time.Hour).Unix(),
		CustomData: map[string]interface{}{
			"role": "user",
		},
	}

	token, err := gen.Generate(claims)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Generated Token:\n%s\n\n", token)

	verified, err := gen.Verify(token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Verified Claims:\n")
	fmt.Printf("  Issuer: %s\n", verified.Issuer)
	fmt.Printf("  Subject: %s\n", verified.Subject)
	fmt.Printf("  Custom Data: %+v\n", verified.CustomData)
}
