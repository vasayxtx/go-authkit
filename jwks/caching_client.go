/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwks

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/acronis/go-appkit/lrucache"
)

const DefaultCacheUpdateMinInterval = time.Minute * 1

// DefaultCacheTTL is a default Time-To-Live duration for cached public keys.
const DefaultCacheTTL = time.Hour * 1

// CachingClientOpts contains options for CachingClient.
type CachingClientOpts struct {
	ClientOpts

	// CacheUpdateMinInterval is a minimal interval between cache updates for the same issuer.
	CacheUpdateMinInterval time.Duration

	// CacheTTL is a Time-To-Live duration for cached public keys.
	// After this duration, cached keys will be considered expired and refetched.
	// This helps ensure that revoked keys are not used indefinitely.
	CacheTTL time.Duration
}

// CachingClient is a Client for getting keys from remote JWKS with a caching mechanism.
type CachingClient struct {
	mu                     sync.RWMutex
	rawClient              *Client
	issuerCache            map[string]issuerCacheEntry
	cacheUpdateMinInterval time.Duration
	cacheTTL               time.Duration
}

const missingKeysCacheSize = 100

type issuerCacheEntry struct {
	updatedAt   time.Time
	keys        map[string]cachedKey
	missingKeys *lrucache.LRUCache[string, time.Time]
}

type cachedKey struct {
	key      interface{}
	cachedAt time.Time
}

// NewCachingClient returns a new Client that can cache fetched data.
func NewCachingClient() *CachingClient {
	return NewCachingClientWithOpts(CachingClientOpts{})
}

// NewCachingClientWithOpts returns a new Client that can cache fetched data with options.
func NewCachingClientWithOpts(opts CachingClientOpts) *CachingClient {
	if opts.CacheUpdateMinInterval == 0 {
		opts.CacheUpdateMinInterval = DefaultCacheUpdateMinInterval
	}
	if opts.CacheTTL == 0 {
		opts.CacheTTL = DefaultCacheTTL
	}
	return &CachingClient{
		rawClient:              NewClientWithOpts(opts.ClientOpts),
		issuerCache:            make(map[string]issuerCacheEntry),
		cacheUpdateMinInterval: opts.CacheUpdateMinInterval,
		cacheTTL:               opts.CacheTTL,
	}
}

// GetRSAPublicKey searches JWK with passed key ID in JWKS and returns decoded RSA public key for it.
// The last one can be used for verifying JWT signature. Obtained JWKS is cached.
// If passed issuer URL or key ID is not found in the cache, JWKS will be fetched again,
// but not more than once in a some (configurable) period of time.
func (cc *CachingClient) GetRSAPublicKey(ctx context.Context, issuerURL, keyID string) (interface{}, error) {
	pubKey, found, needInvalidate := cc.getPubKeyFromCache(issuerURL, keyID)
	if found {
		return pubKey, nil
	}
	if needInvalidate {
		var err error
		if pubKey, found, err = cc.getPubKeyFromCacheAndInvalidate(ctx, issuerURL, keyID); err != nil || found {
			return pubKey, err
		}
	}
	return nil, &JWKNotFoundError{IssuerURL: issuerURL, KeyID: keyID}
}

// InvalidateCacheIfNeeded does cache invalidation for specific issuer URL if it's necessary.
func (cc *CachingClient) InvalidateCacheIfNeeded(ctx context.Context, issuerURL string) error {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	var missingKeys *lrucache.LRUCache[string, time.Time]
	issCache, found := cc.issuerCache[issuerURL]
	if found {
		if time.Since(issCache.updatedAt) < cc.cacheUpdateMinInterval {
			return nil
		}
		missingKeys = issCache.missingKeys
	} else {
		var err error
		if missingKeys, err = lrucache.New[string, time.Time](missingKeysCacheSize, nil); err != nil {
			return fmt.Errorf("new lru cache for missing keys: %w", err)
		}
	}

	pubKeys, err := cc.rawClient.getRSAPubKeysForIssuer(ctx, issuerURL)
	if err != nil {
		return fmt.Errorf("get rsa public keys for issuer %q: %w", issuerURL, err)
	}
	now := time.Now()
	cachedKeys := make(map[string]cachedKey, len(pubKeys))
	for keyID, key := range pubKeys {
		cachedKeys[keyID] = cachedKey{key: key, cachedAt: now}
	}
	cc.issuerCache[issuerURL] = issuerCacheEntry{
		updatedAt:   now,
		keys:        cachedKeys,
		missingKeys: missingKeys,
	}
	return nil
}

func (cc *CachingClient) getPubKeyFromCache(
	issuerURL, keyID string,
) (pubKey interface{}, found bool, needInvalidate bool) {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	issCache, issFound := cc.issuerCache[issuerURL]
	if !issFound {
		return nil, false, true
	}
	if cachedKey, found := issCache.keys[keyID]; found {
		// Check if the cached key has expired
		if time.Since(cachedKey.cachedAt) > cc.cacheTTL {
			return nil, false, true
		}
		return cachedKey.key, true, false
	}
	missedAt, miss := issCache.missingKeys.Get(keyID)
	if !miss || time.Since(missedAt) > cc.cacheUpdateMinInterval {
		return nil, false, true
	}
	return nil, false, false
}

func (cc *CachingClient) getPubKeyFromCacheAndInvalidate(
	ctx context.Context, issuerURL, keyID string,
) (pubKey interface{}, found bool, err error) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	var missingKeys *lrucache.LRUCache[string, time.Time]
	if issCache, issFound := cc.issuerCache[issuerURL]; issFound {
		if cachedKey, found := issCache.keys[keyID]; found {
			// Check if the cached key has expired
			if time.Since(cachedKey.cachedAt) <= cc.cacheTTL {
				return cachedKey.key, true, nil
			}
		}
		missedAt, miss := issCache.missingKeys.Get(keyID)
		if miss && time.Since(missedAt) < cc.cacheUpdateMinInterval {
			return nil, false, nil
		}
		missingKeys = issCache.missingKeys
	} else {
		missingKeys, err = lrucache.New[string, time.Time](missingKeysCacheSize, nil)
		if err != nil {
			return nil, false, fmt.Errorf("new lru cache for missing keys: %w", err)
		}
	}

	pubKeys, err := cc.rawClient.getRSAPubKeysForIssuer(ctx, issuerURL)
	if err != nil {
		return nil, false, fmt.Errorf("get rsa public keys for issuer %q: %w", issuerURL, err)
	}
	pubKey, found = pubKeys[keyID]
	now := time.Now()
	if !found {
		missingKeys.Add(keyID, now)
	}
	cachedKeys := make(map[string]cachedKey, len(pubKeys))
	for id, key := range pubKeys {
		cachedKeys[id] = cachedKey{key: key, cachedAt: now}
	}
	cc.issuerCache[issuerURL] = issuerCacheEntry{
		updatedAt:   now,
		keys:        cachedKeys,
		missingKeys: missingKeys,
	}
	return pubKey, found, nil
}
