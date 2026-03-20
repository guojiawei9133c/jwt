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
go get github.com/guojiawei9133c/jwt
```

## Key Generation

> Use the built-in key generation utilities to create secure keys for JWT signing.

### Generate HMAC Secret Key

```go
package main

import (
    "encoding/hex"
    "fmt"
    "github.com/guojiawei9133c/jwt/pkg/jwt"
)

func main() {
    // Generate HMAC key for HS256
    key256, err := jwt.GenerateHMACKey256()
    if err != nil {
        panic(err)
    }

    // Generate HMAC key for HS384
    key384, err := jwt.GenerateHMACKey384()
    if err != nil {
        panic(err)
    }

    // Generate HMAC key for HS512
    key512, err := jwt.GenerateHMACKey512()
    if err != nil {
        panic(err)
    }

    // Use directly with generator
    gen, err := jwt.NewGenerator(jwt.HS256, key256)
    // ...

    // For storage/display, encode as needed
    keyHex := hex.EncodeToString(key256)
    fmt.Println("HMAC Key (Hex):", keyHex)

    // Or base64
    // keyBase64 := base64.StdEncoding.EncodeToString(key256)
}
```

### Generate ECDSA Key Pair

```go
package main

import (
    "fmt"
    "github.com/guojiawei9133c/jwt/pkg/jwt"
)

func main() {
    // Generate ECDSA key (P256 for ES256)
    priKey, err := jwt.GenerateECDSAKeyP256()
    if err != nil {
        panic(err)
    }

    // Export to PEM format
    privPEM, err := jwt.ExportPrivateKeyPEM(priKey)
    if err != nil {
        panic(err)
    }
    fmt.Println("Private Key:\n", privPEM)

    pubPEM, err := jwt.ExportPublicKeyPEM(&priKey.PublicKey)
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
    "github.com/guojiawei9133c/jwt/pkg/jwt"
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
    "github.com/guojiawei9133c/jwt/pkg/jwt"
)

func main() {
    // Generate a secure key or use existing key
    secret, err := jwt.GenerateHMACKey256()
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
    "github.com/guojiawei9133c/jwt/pkg/jwt"
)

func main() {
    // Generate ECDSA key
    priKey, err := jwt.GenerateECDSAKeyP256()
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
    "github.com/guojiawei9133c/jwt/pkg/jwt"
)

func main() {
    // Step 1: Generate a secure HMAC key
    secretKey, err := jwt.GenerateHMACKey256()
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
    "github.com/guojiawei9133c/jwt/pkg/jwt"
)

func main() {
    // Step 1: Generate ECDSA key
    priKey, err := jwt.GenerateECDSAKeyP256()
    if err != nil {
        panic(err)
    }

    // Step 2: Export keys to PEM format
    privPEM, err := jwt.ExportPrivateKeyPEM(priKey)
    if err != nil {
        panic(err)
    }

    pubPEM, err := jwt.ExportPublicKeyPEM(&priKey.PublicKey)
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

    loadedPriKey, err := jwt.ParseECDSAFromPEM(privData)
    if err != nil {
        panic(err)
    }

    pubKey, err := jwt.ParsePublicKeyFromPEM(pubData)
    if err != nil {
        panic(err)
    }

    // Step 5: Create JWT generator with loaded keys
    gen, err := jwt.NewGeneratorWithECDSA(jwt.ES256, loadedPriKey)
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
    "encoding/base64"
    "encoding/hex"
    "flag"
    "fmt"
    "os"
    "github.com/guojiawei9133c/jwt/pkg/jwt"
)

func main() {
    keyType := flag.String("type", "hmac", "Key type: hmac or ecdsa")
    size := flag.String("size", "256", "HMAC key size: 256/384/512")
    curve := flag.String("curve", "P256", "ECDSA curve (P256/P384/P521)")
    format := flag.String("format", "hex", "Output format: hex or base64 (HMAC only)")
    output := flag.String("output", "", "Output file for PEM (ECDSA only)")
    flag.Parse()

    switch *keyType {
    case "hmac":
        var key []byte
        var err error

        switch *size {
        case "256":
            key, err = jwt.GenerateHMACKey256()
        case "384":
            key, err = jwt.GenerateHMACKey384()
        case "512":
            key, err = jwt.GenerateHMACKey512()
        default:
            fmt.Fprintf(os.Stderr, "Invalid size: %s (use 256/384/512)\n", *size)
            os.Exit(1)
        }

        if err != nil {
            fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            os.Exit(1)
        }

        switch *format {
        case "hex":
            fmt.Println(hex.EncodeToString(key))
        case "base64":
            fmt.Println(base64.StdEncoding.EncodeToString(key))
        default:
            fmt.Fprintf(os.Stderr, "Invalid format: %s\n", *format)
            os.Exit(1)
        }

    case "ecdsa":
        var priKey *ecdsa.PrivateKey
        var err error

        switch *curve {
        case "P256":
            priKey, err = jwt.GenerateECDSAKeyP256()
        case "P384":
            priKey, err = jwt.GenerateECDSAKeyP384()
        case "P521":
            priKey, err = jwt.GenerateECDSAKeyP521()
        default:
            fmt.Fprintf(os.Stderr, "Invalid curve: %s (use P256/P384/P521)\n", *curve)
            os.Exit(1)
        }

        if err != nil {
            fmt.Fprintf(os.Stderr, "Error: %v\n", err)
            os.Exit(1)
        }

        privPEM, _ := jwt.ExportPrivateKeyPEM(priKey)
        pubPEM, _ := jwt.ExportPublicKeyPEM(&priKey.PublicKey)

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
# Generate HMAC key (256 bits)
go run main.go -type hmac -size 256

# Generate HMAC key (384 bits)
go run main.go -type hmac -size 384

# Generate HMAC key (512 bits)
go run main.go -type hmac -size 512

# Generate ECDSA keys
go run main.go -type ecdsa -curve P256 -output mykey
```

## API Reference

### Types

- `SigningMethod`: HS256, HS384, HS512, ES256
- `Claims`: JWT claims with standard and custom fields
- `Token`: Represents a parsed JWT token
- `Generator`: JWT token generator and verifier

### Key Generation Functions

- `GenerateHMACKey256() ([]byte, error)`: Generate 256-bit HMAC key (for HS256)
- `GenerateHMACKey384() ([]byte, error)`: Generate 384-bit HMAC key (for HS384)
- `GenerateHMACKey512() ([]byte, error)`: Generate 512-bit HMAC key (for HS512)
- `GenerateECDSAKeyP256() (*ecdsa.PrivateKey, error)`: Generate P256 ECDSA key (for ES256)
- `GenerateECDSAKeyP384() (*ecdsa.PrivateKey, error)`: Generate P384 ECDSA key (for ES384)
- `GenerateECDSAKeyP521() (*ecdsa.PrivateKey, error)`: Generate P521 ECDSA key (for ES521)
- `ExportPrivateKeyPEM(key *ecdsa.PrivateKey) (string, error)`: Export ECDSA private key to PEM format
- `ExportPublicKeyPEM(key *ecdsa.PublicKey) (string, error)`: Export ECDSA public key to PEM format
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
