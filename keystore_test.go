package jwt

import (
	"testing"
	"time"
)

func TestMemoryKeyStore(t *testing.T) {
	store := NewMemoryKeyStore()

	// Test Set and Get
	store.Set("jti1", []byte("secret1"))
	secret, ok := store.Get("jti1")
	if !ok {
		t.Error("Get() returned false for existing key")
	}
	if string(secret) != "secret1" {
		t.Errorf("Get() = %v, want secret1", string(secret))
	}

	// Test Get non-existent
	_, ok = store.Get("nonexistent")
	if ok {
		t.Error("Get() returned true for non-existent key")
	}

	// Test Delete
	store.Delete("jti1")
	_, ok = store.Get("jti1")
	if ok {
		t.Error("Get() returned true after Delete")
	}
}

func TestMemoryKeyStoreWithTTL(t *testing.T) {
	store := NewMemoryKeyStore()

	// Set with short TTL
	store.SetWithTTL("jti1", []byte("secret1"), 100*time.Millisecond)

	// Should exist immediately
	secret, ok := store.Get("jti1")
	if !ok {
		t.Error("Get() returned false for key with TTL")
	}
	if string(secret) != "secret1" {
		t.Errorf("Get() = %v, want secret1", string(secret))
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	_, ok = store.Get("jti1")
	if ok {
		t.Error("Get() returned true for expired key")
	}
}

func TestMemoryKeyStoreSetOverwrites(t *testing.T) {
	store := NewMemoryKeyStore()

	// Set initial
	store.Set("jti1", []byte("secret1"))

	// Overwrite with TTL
	store.SetWithTTL("jti1", []byte("secret2"), 1*time.Hour)

	secret, ok := store.Get("jti1")
	if !ok {
		t.Error("Get() returned false")
	}
	if string(secret) != "secret2" {
		t.Errorf("Get() = %v, want secret2", string(secret))
	}
}

func TestMemoryKeyStoreConcurrent(t *testing.T) {
	store := NewMemoryKeyStore()
	done := make(chan bool)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(n int) {
			store.Set(string(rune('a'+n)), []byte("secret"))
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all keys exist
	for i := 0; i < 10; i++ {
		jti := string(rune('a' + i))
		_, ok := store.Get(jti)
		if !ok {
			t.Errorf("Key %s not found", jti)
		}
	}
}
