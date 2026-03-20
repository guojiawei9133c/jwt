# JWT - Go JWT Library

A simple and lightweight JWT (JSON Web Token) library for Go.

## Features

- **Multiple Signing Algorithms**: HS256, HS384, HS512 (HMAC) and ES256 (ECDSA)
- **Token Generation**: Create JWT tokens with custom claims
- **Token Verification**: Validate and parse JWT tokens
- **Expiration Handling**: Built-in expiration and not-before validation
- **Custom Claims**: Support for custom data in claims

## Installation

```bash
go get github.com/jwt
```

## Usage

### HMAC Signing (HS256/HS384/HS512)

```go
package main

import (
    "fmt"
    "time"
    "github.com/jwt/pkg/jwt"
)

func main() {
    // Create generator with HMAC
    gen, err := jwt.NewGenerator(jwt.HS256, "your-secret-key")
    if err != nil {
        panic(err)
    }

    // Create claims
    claims := &jwt.Claims{
        Issuer:   "my-app",
        Subject:  "user123",
        Audience: "my-api",
        ExpireAt: time.Now().Add(24 * time.Hour).Unix(),
        CustomData: map[string]interface{}{
            "role": "admin",
            "name": "John Doe",
        },
    }

    // Generate token
    token, err := gen.Generate(claims)
    if err != nil {
        panic(err)
    }
    fmt.Println("Token:", token)

    // Verify token
    verifiedClaims, err := gen.Verify(token)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Verified: %+v\n", verifiedClaims)
}
```

### ECDSA Signing (ES256)

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "github.com/jwt/pkg/jwt"
)

func main() {
    // Generate ECDSA key pair
    priKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil {
        panic(err)
    }

    // Create generator with ECDSA
    gen, err := jwt.NewGeneratorWithECDSA(jwt.ES256, priKey)
    if err != nil {
        panic(err)
    }

    // Set public key for verification
    gen.SetPublicKey(&priKey.PublicKey)

    // Use the same as HMAC example...
}
```

## API Reference

### Types

- `SigningMethod`: HS256, HS384, HS512, ES256
- `Claims`: JWT claims with standard and custom fields
- `Token`: Represents a parsed JWT token
- `Generator`: JWT token generator and verifier

### Functions

- `NewGenerator(method SigningMethod, secret string)`: Create HMAC-based generator
- `NewGeneratorWithECDSA(method SigningMethod, priKey *ecdsa.PrivateKey)`: Create ECDSA-based generator
- `(g *Generator) Generate(claims *Claims) (string, error)`: Generate a JWT token
- `(g *Generator) Verify(token string) (*Claims, error)`: Verify and parse a JWT token
- `(g *Generator) SetPublicKey(pubKey *ecdsa.PublicKey)`: Set public key for ECDSA verification

### Standard Claims

- `iss`: Issuer
- `sub`: Subject
- `aud`: Audience
- `exp`: Expiration time
- `iat`: Issued at
- `nbf`: Not before
- `jti`: JWT ID

### Errors

- `ErrInvalidToken`: Invalid token format
- `ErrInvalidSignature`: Signature verification failed
- `ErrTokenExpired`: Token has expired
- `ErrInvalidKey`: Invalid key provided

## License

MIT License
