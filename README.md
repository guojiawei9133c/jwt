# JWT Library for Go

A lightweight, secure JWT (JSON Web Token) library focusing on ECDSA signatures with practical utilities for production use.

## Why This Library?

**Design Philosophy for AI and Developers:**

1. **Explicit Security**: ECDSA by default (not HMAC), because asymmetric crypto is safer for distributed systems
2. **Two-Phase Verification**: `ParseUnverified` lets you read claims first (to identify issuer/tenant), then verify with the correct key
3. **No Hidden Magic**: All key operations are explicit - you control key generation, storage, and rotation
4. **Production-Ready**: Includes PEM export/import, Bearer token extraction, and proper error handling

## Features

- ✅ **ECDSA Signing**: ES256, ES384, ES512 (P-256, P-384, P-521 curves)
- ✅ **Key Generation**: Built-in secure ECDSA key generation
- ✅ **Two-Phase Verification**: Parse without verification to identify issuer, then verify with correct key
- ✅ **PEM Format Support**: Export/import keys in standard PEM format
- ✅ **Bearer Token Extraction**: Parse `Authorization: Bearer <token>` headers
- ✅ **Type-Safe API**: Full type safety with generics and clear error messages

## Installation

```bash
go get github.com/guojiawei9133c/jwt
```

## Quick Start

### 1. Generate and Sign a Token (ECDSA)

```go
package main

import (
    "fmt"
    "time"
    "github.com/guojiawei9133c/jwt"
)

func main() {
    // Define your claims (use any type, standard MapClaims works)
    claims := jwt.MapClaims{
        "iss": "my-app",
        "sub": "user123",
        "exp": time.Now().Add(24 * time.Hour).Unix(),
        "role": "admin",
    }

    // Generate token with ES256 (automatically generates P-256 key pair)
    token, privateKey, err := jwt.GenerateES256(claims)
    if err != nil {
        panic(err)
    }

    fmt.Println("Token:", token)
    // Save privateKey for verification!
}
```

### 1.5. Sign with Your Existing Key

```go
package main

import (
    "fmt"
    "time"
    "github.com/guojiawei9133c/jwt"
)

func main() {
    // Use your existing private key
    privateKey := loadYourPrivateKey() // Your implementation

    claims := jwt.MapClaims{
        "iss": "my-app",
        "sub": "user123",
        "exp": time.Now().Add(24 * time.Hour).Unix(),
        "role": "admin",
    }

    // Sign with your existing key (no key generation)
    token, err := jwt.SignES256(claims, privateKey)
    if err != nil {
        panic(err)
    }

    fmt.Println("Token:", token)
}
```

### 2. Verify a Token

```go
package main

import (
    "crypto/ecdsa"
    "fmt"
    "github.com/guojiawei9133c/jwt"
)

func verifyToken(tokenString string, publicKey *ecdsa.PublicKey) error {
    // Verify signature
    valid, err := jwt.VerifyJWT(tokenString, publicKey)
    if err != nil {
        return err
    }

    if !valid {
        return fmt.Errorf("invalid signature")
    }

    fmt.Println("Token is valid!")
    return nil
}
```

### 3. Two-Phase Verification (Multi-Tenant Systems)

**Why?** In multi-tenant systems, different issuers use different keys. You need to read the issuer claim BEFORE verification to know which key to use.

```go
package main

import (
    "fmt"
    "github.com/guojiawei9133c/jwt"
)

func verifyMultiTenantToken(tokenString string) error {
    // Phase 1: Parse WITHOUT verification to read claims
    token, err := jwt.ParseUnverified(tokenString)
    if err != nil {
        return err
    }

    // Extract issuer to lookup the correct verification key
    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return fmt.Errorf("invalid claims type")
    }
    issuer, ok := claims["iss"].(string)
    if !ok {
        return fmt.Errorf("missing or invalid issuer claim")
    }
    fmt.Println("Token from issuer:", issuer)

    // Phase 2: Lookup the public key for this issuer
    publicKey := lookupPublicKey(issuer) // Your implementation

    // Phase 3: Verify with the correct key
    valid, err := jwt.VerifyJWT(tokenString, publicKey)
    if err != nil {
        return err
    }

    if !valid {
        return fmt.Errorf("invalid signature for issuer: %s", issuer)
    }

    fmt.Printf("Verified token from %s\n", issuer)
    return nil
}
```

## Key Management

### Generate ECDSA Keys

```go
package main

import (
    "fmt"
    "github.com/guojiawei9133c/jwt"
)

func main() {
    // Generate P-256 key (for ES256)
    privateKey, err := jwt.GenerateECDSAKeyP256()
    if err != nil {
        panic(err)
    }

    // Get public key
    publicKey := &privateKey.PublicKey

    fmt.Println("Generated P-256 key pair")
}
```

### Export Keys to PEM

```go
package main

import (
    "fmt"
    "os"
    "github.com/guojiawei9133c/jwt"
)

func main() {
    privateKey, _ := jwt.GenerateECDSAKeyP256()

    // Export to PEM format (for storage)
    privPEM, err := jwt.PrivateKeyToPEM(privateKey)
    if err != nil {
        panic(err)
    }

    fmt.Println("Private Key (PEM):")
    fmt.Println(string(privPEM))

    // Save to file
    os.WriteFile("private.pem", privPEM, 0600)
}
```

### Load Keys from PEM

```go
package main

import (
    "os"
    "github.com/guojiawei9133c/jwt"
)

func main() {
    // Read from file
    pemData, err := os.ReadFile("private.pem")
    if err != nil {
        panic(err)
    }

    // Parse PEM
    privateKey, err := jwt.PEMToPrivateKey(pemData)
    if err != nil {
        panic(err)
    }

    // Use privateKey...
}
```

## HTTP Integration

### Extract Bearer Token from Authorization Header

```go
package main

import (
    "net/http"
    "github.com/guojiawei9133c/jwt"
)

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Extract token from "Authorization: Bearer <token>" header
        tokenString, err := jwt.ExtractBearerToken(r.Header.Get("Authorization"))
        if err != nil {
            http.Error(w, "Invalid authorization header", http.StatusUnauthorized)
            return
        }

        // Verify token
        // ... (use your verification logic here)

        next.ServeHTTP(w, r)
    })
}
```

## Complete Examples

### Example 1: Token Generation and Verification Workflow

```go
package main

import (
    "fmt"
    "time"
    "github.com/guojiawei9133c/jwt"
)

func main() {
    // Step 1: Generate key pair (do this once, store securely)
    privateKey, err := jwt.GenerateECDSAKeyP256()
    if err != nil {
        panic(err)
    }
    publicKey := &privateKey.PublicKey

    // Step 2: Create claims
    claims := jwt.MapClaims{
        "iss": "my-auth-service",
        "sub": "user-12345",
        "exp": time.Now().Add(24 * time.Hour).Unix(),
        "role": "admin",
        "email": "user@example.com",
    }

    // Step 3: Generate token
    token, _, err := jwt.GenerateES256(claims)
    if err != nil {
        panic(err)
    }
    fmt.Println("Generated Token:", token)

    // Step 4: Verify token
    valid, err := jwt.VerifyJWT(token, publicKey)
    if err != nil {
        panic(err)
    }

    if valid {
        fmt.Println("✅ Token is valid!")
    } else {
        fmt.Println("❌ Token is invalid!")
    }
}
```

### Example 1.5: Using Existing Keys for Signing

```go
package main

import (
    "fmt"
    "time"
    "github.com/guojiawei9133c/jwt"
)

func main() {
    // Step 1: Use your existing key pair (from environment, file, etc.)
    privateKey := loadYourPrivateKey() // Your implementation
    publicKey := &privateKey.PublicKey

    // Step 2: Create claims
    claims := jwt.MapClaims{
        "iss": "my-app",
        "sub": "user-67890",
        "exp": time.Now().Add(1 * time.Hour).Unix(),
        "permissions": []string{"read", "write"},
    }

    // Step 3: Sign with existing key using SignES256
    token, err := jwt.SignES256(claims, privateKey)
    if err != nil {
        panic(err)
    }
    fmt.Println("Generated Token:", token)

    // Step 4: Verify token
    valid, err := jwt.VerifyJWT(token, publicKey)
    if err != nil {
        panic(err)
    }

    if valid {
        fmt.Println("✅ Token is valid!")
    } else {
        fmt.Println("❌ Token is invalid!")
    }
}

// Example: Load private key from environment or file
func loadYourPrivateKey() *ecdsa.PrivateKey {
    // In production, load from secure storage
    key, _ := jwt.GenerateECDSAKeyP256()
    return key
}
```

### Example 1.6: Public Key Export/Import

```go
package main

import (
    "fmt"
    "os"
    "github.com/guojiawei9133c/jwt"
)

func main() {
    // Generate key pair
    privateKey, _ := jwt.GenerateECDSAKeyP256()
    publicKey := &privateKey.PublicKey

    // Export public key to PEM (for sharing with verification services)
    pubPEM, err := jwt.PublicKeyToPEM(publicKey)
    if err != nil {
        panic(err)
    }

    // Save public key to file (can be freely distributed)
    os.WriteFile("public.pem", pubPEM, 0644)
    fmt.Println("Public key saved to public.pem")
    fmt.Println(string(pubPEM))

    // Import public key from PEM (for verification)
    pubData, _ := os.ReadFile("public.pem")
    loadedPublicKey, err := jwt.PEMToPublicKey(pubData)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Successfully loaded public key: %v\n", loadedPublicKey != nil)
}
```

### Example 2: Multi-Tenant Authentication System

```go
package main

import (
    "crypto/ecdsa"
    "fmt"
    "sync"
    "time"
    "github.com/guojiawei9133c/jwt"
)

// KeyStore manages public keys for different issuers
type KeyStore struct {
    keys map[string]*ecdsa.PublicKey
    mu   sync.RWMutex
}

func NewKeyStore() *KeyStore {
    return &KeyStore{
        keys: make(map[string]*ecdsa.PublicKey),
    }
}

func (ks *KeyStore) Add(issuer string, publicKey *ecdsa.PublicKey) {
    ks.mu.Lock()
    defer ks.mu.Unlock()
    ks.keys[issuer] = publicKey
}

func (ks *KeyStore) Get(issuer string) (*ecdsa.PublicKey, bool) {
    ks.mu.RLock()
    defer ks.mu.RUnlock()
    key, ok := ks.keys[issuer]
    return key, ok
}

func main() {
    // Setup: Initialize key store with keys for different issuers
    keyStore := NewKeyStore()

    // Add keys for app1 and app2
    priKey1, _ := jwt.GenerateECDSAKeyP256()
    priKey2, _ := jwt.GenerateECDSAKeyP256()

    keyStore.Add("app1", &priKey1.PublicKey)
    keyStore.Add("app2", &priKey2.PublicKey)

    // Simulate receiving a token from app1
    claims := jwt.MapClaims{
        "iss": "app1",
        "sub": "user123",
        "exp": time.Now().Add(24 * time.Hour).Unix(),
    }
    token, _, _ := jwt.GenerateES256(claims)

    // Verify the token using two-phase approach
    // Phase 1: Parse to identify issuer
    parsedToken, err := jwt.ParseUnverified(token)
    if err != nil {
        panic(err)
    }

    tokenClaims, ok := parsedToken.Claims.(jwt.MapClaims)
    if !ok {
        panic("invalid claims type")
    }
    issuer, ok := tokenClaims["iss"].(string)
    if !ok {
        panic("missing or invalid issuer claim")
    }

    // Phase 2: Lookup key for this issuer
    publicKey, ok := keyStore.Get(issuer)
    if !ok {
        panic(fmt.Sprintf("Unknown issuer: %s", issuer))
    }

    // Phase 3: Verify with the correct key
    valid, err := jwt.VerifyJWT(token, publicKey)
    if err != nil {
        panic(err)
    }

    if valid {
        fmt.Printf("✅ Verified token from %s\n", issuer)
    }
}
```

### Example 3: HTTP Authentication Middleware

```go
package main

import (
    "crypto/ecdsa"
    "net/http"
    "github.com/guojiawei9133c/jwt"
)

// Auth middleware that validates JWT tokens
func JWTAuth(publicKey *ecdsa.PublicKey) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // Extract Bearer token
            tokenString, err := jwt.ExtractBearerToken(r.Header.Get("Authorization"))
            if err != nil {
                http.Error(w, "Missing or invalid authorization header", http.StatusUnauthorized)
                return
            }

            // Verify token
            valid, err := jwt.VerifyJWT(tokenString, publicKey)
            if err != nil {
                http.Error(w, "Invalid token", http.StatusUnauthorized)
                return
            }

            if !valid {
                http.Error(w, "Invalid signature", http.StatusUnauthorized)
                return
            }

            // Token is valid, proceed to next handler
            next.ServeHTTP(w, r)
        })
    }
}

func main() {
    // Load your public key
    publicKey := loadPublicKey() // Your implementation

    // Use middleware
    http.Handle("/api/protected", JWTAuth(publicKey)(http.HandlerFunc(handler)))
    http.ListenAndServe(":8080", nil)
}

func handler(w http.ResponseWriter, r *http.Request) {
    w.Write([]byte("Access granted!"))
}
```

### Example 3.5: Token Expiration Check

```go
package main

import (
    "fmt"
    "time"
    "github.com/guojiawei9133c/jwt"
)

func main() {
    // Create an expired token
    claims := jwt.MapClaims{
        "iss": "my-app",
        "sub": "user123",
        "exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
    }

    token, _, _ := jwt.GenerateES256(claims)

    // Parse and check expiration
    parsedToken, err := jwt.ParseUnverified(token)
    if err != nil {
        panic(err)
    }

    expired, err := jwt.IsExpired(parsedToken)
    if err != nil {
        panic(err)
    }

    if expired {
        fmt.Println("⚠️ Token has expired!")
    } else {
        fmt.Println("✅ Token is still valid")
    }
}
```

## API Reference

### Token Generation

#### Auto-Generate Keys (Simplest)

| Function | Description | Algorithm |
|----------|-------------|-----------|
| `GenerateES256(claims)` | Generate JWT with ES256 (auto-generates key) | ECDSA P-256 + SHA-256 |
| `GenerateES384(claims)` | Generate JWT with ES384 (auto-generates key) | ECDSA P-384 + SHA-384 |
| `GenerateES512(claims)` | Generate JWT with ES512 (auto-generates key) | ECDSA P-521 + SHA-512 |

Returns: `(token string, privateKey *ecdsa.PrivateKey, error error)`

#### Sign with Existing Keys (Advanced)

| Function | Description | Algorithm |
|----------|-------------|-----------|
| `SignES256(claims, privateKey)` | Sign JWT with ES256 using your key | ECDSA P-256 + SHA-256 |
| `SignES384(claims, privateKey)` | Sign JWT with ES384 using your key | ECDSA P-384 + SHA-384 |
| `SignES512(claims, privateKey)` | Sign JWT with ES512 using your key | ECDSA P-521 + SHA-512 |

Returns: `(token string, error error)`

### Token Verification

| Function | Description |
|----------|-------------|
| `VerifyJWT(token, publicKey)` | Verify ECDSA signature |
| `IsExpired(token)` | Check if token is expired |

Returns:
- `VerifyJWT`: `(valid bool, error error)`
- `IsExpired`: `(expired bool, error error)`

### Two-Phase Parsing

| Function | Description | Use Case |
|----------|-------------|----------|
| `ParseUnverified(token)` | Parse JWT without verifying signature | Multi-tenant systems, key lookup |

Returns: `(*jwt.Token, error)`

**⚠️ Security Warning**: Claims from `ParseUnverified` are not verified. Always call `VerifyJWT` before trusting the data.

### Key Generation

| Function | Description | Curve |
|----------|-------------|-------|
| `GenerateECDSAKeyP256()` | Generate P-256 key | For ES256 |
| `GenerateECDSAKeyP384()` | Generate P-384 key | For ES384 |
| `GenerateECDSAKeyP521()` | Generate P-521 key | For ES512 |

Returns: `(*ecdsa.PrivateKey, error)`

### PEM Export/Import

#### Private Key

| Function | Description |
|----------|-------------|
| `PrivateKeyToPEM(key)` | Export private key to PEM |
| `PEMToPrivateKey(pemData)` | Import private key from PEM |
| `PrivateKeyToBytes(key)` | Export private key to bytes |
| `BytesToPrivateKey(data)` | Import private key from bytes |

#### Public Key

| Function | Description |
|----------|-------------|
| `PublicKeyToPEM(key)` | Export public key to PEM |
| `PEMToPublicKey(pemData)` | Import public key from PEM |
| `PublicKeyToBytes(key)` | Export public key to bytes |
| `BytesToPublicKey(data)` | Import public key from bytes |

### HTTP Utilities

| Function | Description |
|----------|-------------|
| `ExtractBearerToken(authHeader)` | Extract token from `Authorization: Bearer <token>` |

## Best Practices

### 1. Key Management

✅ **DO**:
- Generate keys once and store them securely
- Use environment variables or secret management for keys
- Use different keys for different environments (dev/staging/prod)
- Rotate keys periodically

❌ **DON'T**:
- Generate new keys for every token (except per-token security model)
- Commit keys to version control
- Log private keys
- Use the same key across all services

### 2. Token Verification

✅ **DO**:
- Always verify tokens on the server side
- Check expiration time (`exp` claim)
- Use two-phase verification for multi-tenant systems

❌ **DON'T**:
- Trust tokens without verification
- Use `ParseUnverified` and skip `VerifyJWT`
- Verify tokens only on client side

### 3. Security

✅ **DO**:
- Use ES256 (P-256) for most applications
- Use ES384/ES512 for higher security requirements
- Set appropriate expiration times
- Include issuer (`iss`) and audience (`aud`) claims

❌ **DON'T**:
- Set expiration too far in the future
- Store sensitive data in claims (JWTs are not encrypted!)
- Use weak key sizes

## Algorithm Selection

| Algorithm | Curve | Security | Performance | Use Case |
|-----------|-------|----------|-------------|----------|
| ES256 | P-256 | High | Fast | Most applications |
| ES384 | P-384 | Very High | Medium | High-security requirements |
| ES512 | P-521 | Extremely High | Slower | Maximum security |

**Recommendation**: Use ES256 (P-256) for most applications. It provides excellent security with good performance.

## Error Handling

```go
import (
    "strings"
    "github.com/guojiawei9133c/jwt"
)

token, privateKey, err := jwt.GenerateES256(claims)
if err != nil {
    // Handle specific errors
    switch {
    case strings.Contains(err.Error(), "failed to generate"):
        // Key generation error
    case strings.Contains(err.Error(), "failed to sign"):
        // Signing error
    default:
        // Unknown error
    }
    panic(err)
}
```

## Contributing

Contributions are welcome! Please ensure:
- All tests pass: `go test ./...`
- Code is formatted: `go fmt ./...`
- New features include tests and documentation

## License

MIT License - see LICENSE file for details

## Why ECDSA Instead of HMAC?

This library focuses on ECDSA rather than HMAC because:

1. **Asymmetric Security**: Public keys can be freely distributed while private keys remain secret
2. **Scalability**: Verify tokens without sharing secrets across services
3. **Compromise Containment**: If a verifier is compromised, the signing key is still safe
4. **Multi-Tenant Friendly**: Different issuers with different keys

For most production systems, ECDSA is the safer choice.
