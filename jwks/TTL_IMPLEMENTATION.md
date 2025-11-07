# JWKS Cache TTL Implementation

## Summary

Fixed a critical security bug in the JWKS caching client where cached public keys never expired, potentially allowing the use of revoked keys indefinitely. Added TTL (Time-To-Live) support to automatically expire cache entries after a configurable duration.

## Changes Made

### 1. Added TTL Configuration (`jwks/caching_client.go`)

#### New Constants
- `DefaultCacheTTL = 1 hour` - Default expiration time for cached keys

#### Updated `CachingClientOpts`
- Added `CacheTTL time.Duration` field with documentation explaining its security purpose

#### Updated `CachingClient`
- Added `cacheTTL time.Duration` field to track TTL configuration

#### Updated `issuerCacheEntry`
- Added `expiresAt time.Time` field to track when each cache entry expires

### 2. Modified Cache Behavior

#### `NewCachingClientWithOpts`
- Sets default TTL to 1 hour if not specified
- Initializes `cacheTTL` field

#### `InvalidateCacheIfNeeded`
- Now checks both TTL expiration and update interval
- Only skips update if cache is still valid AND update interval hasn't passed
- Sets `expiresAt` when creating new cache entries

#### `getPubKeyFromCache`
- Added TTL expiration check before returning cached keys
- Returns `needInvalidate=true` if cache has expired

#### `getPubKeyFromCacheAndInvalidate`
- Added TTL expiration check before using cached keys
- Ensures expired keys are not returned even in concurrent scenarios
- Sets `expiresAt` when creating new cache entries

### 3. Comprehensive Test Coverage (`jwks/caching_client_test.go`)

Added `TestCachingClient_TTLExpiration` with four test scenarios:

1. **Cache expires after TTL**
   - Verifies cache is used before expiration
   - Verifies cache is refreshed after expiration
   - Uses short TTL (500ms) for fast testing

2. **Default TTL is 1 hour**
   - Verifies default behavior when TTL is not specified
   - Confirms cache remains valid for multiple requests

3. **Concurrent requests after TTL expiration**
   - Tests thread-safety during cache expiration
   - Verifies only one refresh occurs despite concurrent requests

4. **Custom TTL configuration**
   - Tests custom TTL values
   - Verifies cache behavior at different time intervals

## Security Benefits

1. **Prevents use of revoked keys**: Keys are automatically refreshed after TTL expires
2. **Configurable security window**: Organizations can adjust TTL based on their security requirements
3. **Backward compatible**: Default 1-hour TTL provides reasonable security without breaking existing code
4. **Balanced performance**: TTL works with existing `CacheUpdateMinInterval` to prevent excessive API calls

## Usage Examples

### Using Default TTL (1 hour)
```go
client := jwks.NewCachingClient()
```

### Custom TTL (15 minutes)
```go
client := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
    CacheTTL: 15 * time.Minute,
})
```

### Short TTL for high-security environments (5 minutes)
```go
client := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
    CacheTTL:               5 * time.Minute,
    CacheUpdateMinInterval: 30 * time.Second,
})
```

## Test Results

All tests pass successfully:
```
=== RUN   TestCachingClient_GetRSAPublicKey
--- PASS: TestCachingClient_GetRSAPublicKey (2.01s)

=== RUN   TestCachingClient_TTLExpiration
--- PASS: TestCachingClient_TTLExpiration (1.62s)
    --- PASS: cache_expires_after_TTL (0.61s)
    --- PASS: default_TTL_is_1_hour (0.00s)
    --- PASS: concurrent_requests_after_TTL_expiration (0.60s)
    --- PASS: custom_TTL_configuration (0.41s)

=== RUN   TestClient_GetRSAPublicKey
--- PASS: TestClient_GetRSAPublicKey (0.28s)
```

## Migration Guide

This change is **fully backward compatible**. Existing code will automatically use the default 1-hour TTL:

```go
// Existing code continues to work with new security benefits
client := jwks.NewCachingClient()
// or
client := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
    CacheUpdateMinInterval: time.Minute * 5,
})
```

To customize TTL for specific security requirements:

```go
client := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
    CacheUpdateMinInterval: time.Minute * 5,
    CacheTTL:               time.Minute * 30, // Keys expire after 30 minutes
})
```

## Best Practices

1. **Default TTL (1 hour)**: Suitable for most production environments
2. **Shorter TTL (15-30 minutes)**: Recommended for high-security environments
3. **Longer TTL (2-4 hours)**: Only for development/testing or low-risk scenarios
4. **Balance with CacheUpdateMinInterval**: Ensure TTL > CacheUpdateMinInterval to allow caching benefits
