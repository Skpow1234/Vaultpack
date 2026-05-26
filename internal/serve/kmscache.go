package serve

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

// KMSCache is an in-memory, TTL-bounded cache for KMS unwrap results.
//
// The cache key is a SHA-256 over (provider, keyID, wrappedDEK) — the
// three inputs that uniquely identify an unwrap operation. The value is
// the unwrapped DEK bytes.
//
// Entries expire after TTL. When the cache exceeds MaxSize, entries are
// evicted in insertion order (FIFO) to keep the implementation small;
// for VaultPack workloads the working set is tiny (one DEK per bundle
// version) so a more sophisticated LRU is overkill.
//
// All methods are safe for concurrent use.
type KMSCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	order   []string // FIFO eviction order
	ttl     time.Duration
	maxSize int

	hits   atomic.Uint64
	misses atomic.Uint64
	evicts atomic.Uint64
}

type cacheEntry struct {
	dek       []byte
	expiresAt time.Time
}

// NewKMSCache returns a new cache. ttl <= 0 means "never expire";
// maxSize <= 0 means "unbounded" (not recommended).
func NewKMSCache(ttl time.Duration, maxSize int) *KMSCache {
	return &KMSCache{
		entries: make(map[string]cacheEntry),
		ttl:     ttl,
		maxSize: maxSize,
	}
}

// CacheKey computes the stable cache key for an unwrap tuple.
func CacheKey(provider, keyID string, wrappedDEK []byte) string {
	h := sha256.New()
	h.Write([]byte(provider))
	h.Write([]byte{0})
	h.Write([]byte(keyID))
	h.Write([]byte{0})
	h.Write(wrappedDEK)
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns the cached DEK for key, or (nil, false) if absent or expired.
func (c *KMSCache) Get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		c.misses.Add(1)
		return nil, false
	}
	if c.ttl > 0 && time.Now().After(e.expiresAt) {
		delete(c.entries, key)
		c.removeFromOrder(key)
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	out := make([]byte, len(e.dek))
	copy(out, e.dek)
	return out, true
}

// Put stores dek under key. The cache copies dek; the caller may reuse the buffer.
func (c *KMSCache) Put(key string, dek []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		c.order = append(c.order, key)
	}
	copyDEK := make([]byte, len(dek))
	copy(copyDEK, dek)
	var exp time.Time
	if c.ttl > 0 {
		exp = time.Now().Add(c.ttl)
	}
	c.entries[key] = cacheEntry{dek: copyDEK, expiresAt: exp}

	for c.maxSize > 0 && len(c.order) > c.maxSize {
		evict := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, evict)
		c.evicts.Add(1)
	}
}

func (c *KMSCache) removeFromOrder(key string) {
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}

// Stats returns a snapshot of cache statistics.
func (c *KMSCache) Stats() KMSCacheStats {
	c.mu.Lock()
	size := len(c.entries)
	c.mu.Unlock()
	return KMSCacheStats{
		Size:    size,
		Hits:    c.hits.Load(),
		Misses:  c.misses.Load(),
		Evicted: c.evicts.Load(),
	}
}

// KMSCacheStats is a snapshot of cache counters.
type KMSCacheStats struct {
	Size    int
	Hits    uint64
	Misses  uint64
	Evicted uint64
}
