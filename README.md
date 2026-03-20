# JWT - Go JWT Library

A simple and lightweight JWT (JSON Web Token) library for Go.

## Features

- **Multiple Signing Algorithms**: HS256, HS384, HS512 (HMAC) and ES256 (ECDSA)
- **Key Generation**: Built-in utilities for generating HMAC and ECDSA keys
- **Token Generation**: Create JWT tokens with custom claims
- **Token Verification**: Validate and parse JWT tokens
- **Expiration Handling**: Built-in expiration and not-before validation
- **Custom Claims**: Support for custom data in claims
- **PEM Export/Import**: Save and load ECDSA keys in PEM format

## Installation

```bash
go get github.com/jwt
```

## Key Generation

> Use the built-in key generation utilities to create secure keys for JWT signing.

### Generate HMAC Secret Key

```go
package main

import (
    "encoding/hex"
    "fmt"
    "github.com/jwt/pkg/jwt"
)

func main() {
    // Generate raw HMAC key (returns []byte)
    key, err := jwt.GenerateHMACKey(256)  // 256 bits for HS256
    if err != nil {
        panic(err)
    }
    fmt.Println("HMAC Key (raw):", key)

    // Or get hex encoded string
    keyHex, err := jwt.GenerateHMACKeyHex(256)
    if err != nil {
        panic(err)
    }
    fmt.Println("HMAC Key (Hex):", keyHex)

    // Or get Base64 encoded string
    keyBase64, err := jwt.GenerateHMACKeyBase64(256)
    if err != nil {
        panic(err)
    }
    fmt.Println("HMAC Key (Base64):", keyBase64)

    // Use raw key with generator
    gen, err := jwt.NewGenerator(jwt.HS256, key)
    // ...
}
```

### Generate ECDSA Key Pair

```go
package main

import (
    "fmt"
    "github.com/jwt/pkg/jwt"
)

func main() {
    // Generate ECDSA key pair (P256 for ES256)
    kp, err := jwt.GenerateECDSAKeyPair("P256")
    if err != nil {
        panic(err)
    }

    // Export to PEM format
    privPEM, err := kp.PrivateKeyPEM()
    if err != nil {
        panic(err)
    }
    fmt.Println("Private Key:\n", privPEM)

    pubPEM, err := kp.PublicKeyPEM()
    if err != nil {
        panic(err)
    }
    fmt.Println("Public Key:\n", pubPEM)

    // Save to files
    // os.WriteFile("private.pem", []byte(privPEM), 0600)
    // os.WriteFile("public.pem", []byte(pubPEM), 0644)
}
```

### Load ECDSA Key from PEM

```go
package main

import (
    "os"
    "github.com/jwt/pkg/jwt"
)

func main() {
    // Read from file
    privPEM, _ := os.ReadFile("private.pem")
    pubPEM, _ := os.ReadFile("public.pem")

    // Parse keys
    priKey, err := jwt.ParseECDSAFromPEM(privPEM)
    if err != nil {
        panic(err)
    }

    pubKey, err := jwt.ParsePublicKeyFromPEM(pubPEM)
    if err != nil {
        panic(err)
    }

    // Use with generator
    gen, err := jwt.NewGeneratorWithECDSA(jwt.ES256, priKey)
    if err != nil {
        panic(err)
    }
    gen.SetPublicKey(pubKey)
    // ...
}
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
    // Generate a secure key or use existing key
    secret, err := jwt.GenerateHMACKey(256)
    if err != nil {
        panic(err)
    }

    // Create generator with HMAC
    gen, err := jwt.NewGenerator(jwt.HS256, secret)
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

---

## Complete Examples

### Example 1: HMAC JWT - Complete Workflow

```go
package main

import (
    "encoding/hex"
    "fmt"
    "time"
    "github.com/jwt/pkg/jwt"
)

func main() {
    // Step 1: Generate a secure HMAC key
    secretKey, err := jwt.GenerateHMACKey(256)
    if err != nil {
        panic(err)
    }
    fmt.Println("Generated Secret Key (Hex):", hex.EncodeToString(secretKey))

    // Step 2: Create JWT generator
    gen, err := jwt.NewGenerator(jwt.HS256, secretKey)
    if err != nil {
        panic(err)
    }

    // Step 3: Create claims with user data
    claims := &jwt.Claims{
        Issuer:   "my-auth-service",
        Subject:  "user-12345",
        Audience: "my-api",
        ExpireAt: time.Now().Add(24 * time.Hour).Unix(),
        CustomData: map[string]interface{}{
            "role":    "admin",
            "email":   "user@example.com",
            "name":    "John Doe",
        },
    }

    // Step 4: Generate JWT token
    token, err := gen.Generate(claims)
    if err != nil {
        panic(err)
    }
    fmt.Println("Generated Token:", token)

    // Step 5: Verify and parse token
    verifiedClaims, err := gen.Verify(token)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Verified Claims: iss=%s, sub=%s, role=%s\n",
        verifiedClaims.Issuer,
        verifiedClaims.Subject,
        verifiedClaims.CustomData["role"])
}
```

### Example 2: ECDSA JWT - Generate, Save, Load & Use

```go
package main

import (
    "fmt"
    "os"
    "time"
    "github.com/jwt/pkg/jwt"
)

func main() {
    // Step 1: Generate ECDSA key pair
    kp, err := jwt.GenerateECDSAKeyPair("P256")
    if err != nil {
        panic(err)
    }

    // Step 2: Export keys to PEM format
    privPEM, err := kp.PrivateKeyPEM()
    if err != nil {
        panic(err)
    }

    pubPEM, err := kp.PublicKeyPEM()
    if err != nil {
        panic(err)
    }

    // Step 3: Save keys to files (for production use)
    os.WriteFile("private.pem", []byte(privPEM), 0600)
    os.WriteFile("public.pem", []byte(pubPEM), 0644)
    fmt.Println("Keys saved to private.pem and public.pem")

    // Step 4: Load keys from files (simulating production)
    privData, _ := os.ReadFile("private.pem")
    pubData, _ := os.ReadFile("public.pem")

    priKey, err := jwt.ParseECDSAFromPEM(privData)
    if err != nil {
        panic(err)
    }

    pubKey, err := jwt.ParsePublicKeyFromPEM(pubData)
    if err != nil {
        panic(err)
    }

    // Step 5: Create JWT generator with loaded keys
    gen, err := jwt.NewGeneratorWithECDSA(jwt.ES256, priKey)
    if err != nil {
        panic(err)
    }
    gen.SetPublicKey(pubKey)

    // Step 6: Generate and verify token
    claims := &jwt.Claims{
        Issuer:   "secure-app",
        Subject:  "user-67890",
        ExpireAt: time.Now().Add(7 * 24 * time.Hour).Unix(), // 7 days
        CustomData: map[string]interface{}{
            "permissions": []string{"read", "write", "delete"},
        },
    }

    token, err := gen.Generate(claims)
    if err != nil {
        panic(err)
    }
    fmt.Println("Generated Token:", token)

    // Verify token
    verifiedClaims, err := gen.Verify(token)
    if err != nil {
        panic(err)
    }
    fmt.Printf("Verified: %s has permissions: %v\n",
        verifiedClaims.Subject,
        verifiedClaims.CustomData["permissions"])

    // Cleanup demo files
    os.Remove("private.pem")
    os.Remove("public.pem")
}
```

### Example 3: CLI Tool for Key Generation

```go
package main

import (
    "encoding/hex"
    "flag"
    "fmt"
    "os"
    "github.com/jwt/pkg/jwt"
)

func main() {
    keyType := flag.String("type", "hmac", "Key type: hmac or ecdsa")
    bits := flag.Int("bits", 256, "HMAC key size in bits (256/384/512)")
    curve := flag.String("curve", "P256", "ECDSA curve (P256/P384/P521)")
    format := flag.String("format", "hex", "Output format: hex or base64 (HMAC only)")
    output := flag.String("output", "", "Output file for PEM (ECDSA only)")
    flag.Parse()

    switch *keyType {
    case "hmac":
        key, err := jwt.GenerateHMACKey(*bits)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            os.Exit(1)
        }

        switch *format {
        case "hex":
            fmt.Println(hex.EncodeToString(key))
        case "base64":
            b64, _ := jwt.GenerateHMACKeyBase64(*bits)
            fmt.Println(b64)
        default:
            fmt.Fprintf(os.Stderr, "Invalid format: %s\n", *format)
            os.Exit(1)
        }

    case "ecdsa":
        kp, err := jwt.GenerateECDSAKeyPair(*curve)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            os.Exit(1)
        }

        privPEM, _ := kp.PrivateKeyPEM()
        pubPEM, _ := kp.PublicKeyPEM()

        if *output != "" {
            os.WriteFile(*output+".pem", []byte(privPEM), 0600)
            os.WriteFile(*output+".pub.pem", []byte(pubPEM), 0644)
            fmt.Printf("Keys saved to %s.pem and %s.pub.pem\n", *output, *output)
        } else {
            fmt.Println("----- PRIVATE KEY -----")
            fmt.Println(privPEM)
            fmt.Println("----- PUBLIC KEY -----")
            fmt.Println(pubPEM)
        }

    default:
        fmt.Fprintf(os.Stderr, "Invalid key type: %s\n", *keyType)
        os.Exit(1)
    }
}
```

Run the CLI tool:
```bash
# Generate HMAC key (hex format)
go run main.go -type hmac -bits 256 -format hex

# Generate HMAC key (base64 format)
go run main.go -type hmac -bits 256 -format base64

# Generate ECDSA keys
go run main.go -type ecdsa -curve P256 -output mykey
```

## API Reference

### Types

- `SigningMethod`: HS256, HS384, HS512, ES256
- `Claims`: JWT claims with standard and custom fields
- `Token`: Represents a parsed JWT token
- `Generator`: JWT token generator and verifier
- `ECDSAKeyPair`: ECDSA key pair container

### Key Generation Functions

- `GenerateHMACKey(bits int) ([]byte, error)`: Generate random HMAC key (raw bytes)
- `GenerateHMACKeyHex(bits int) (string, error)`: Generate random HMAC key (hex encoded)
- `GenerateHMACKeyBase64(bits int) (string, error)`: Generate random HMAC key (Base64 encoded)
- `GenerateECDSAKeyPair(curve string) (*ECDSAKeyPair, error)`: Generate ECDSA key pair (supports P256, P384, P521)
- `(kp *ECDSAKeyPair) PrivateKeyPEM() (string, error)`: Export private key to PEM format
- `(kp *ECDSAKeyPair) PublicKeyPEM() (string, error)`: Export public key to PEM format
- `ParseECDSAFromPEM(pemData []byte) (*ecdsa.PrivateKey, error)`: Parse ECDSA private key from PEM
- `ParsePublicKeyFromPEM(pemData []byte) (*ecdsa.PublicKey, error)`: Parse public key from PEM

### Generator Functions

- `NewGenerator(method SigningMethod, secret []byte) (*Generator, error)`: Create HMAC-based generator
- `NewGeneratorWithECDSA(method SigningMethod, priKey *ecdsa.PrivateKey) (*Generator, error)`: Create ECDSA-based generator
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
