/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package jwks_test

import (
	"context"
	"crypto/rsa"
	"errors"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/jwks"
)

func TestCachingClient_GetRSAPublicKey(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{CacheUpdateMinInterval: time.Second * 10})
		var wg sync.WaitGroup
		const callsNum = 10
		wg.Add(callsNum)
		errs := make(chan error, callsNum)
		pubKeys := make(chan interface{}, callsNum)
		for i := 0; i < callsNum; i++ {
			go func() {
				defer wg.Done()
				pubKey, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
				if err != nil {
					errs <- err
					return
				}
				pubKeys <- pubKey
			}()
		}
		wg.Wait()
		close(errs)
		close(pubKeys)
		for err := range errs {
			require.NoError(t, err)
		}
		for pubKey := range pubKeys {
			require.NotNil(t, pubKey)
			require.IsType(t, &rsa.PublicKey{}, pubKey)
		}
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())
	})

	t.Run("jwk not found", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const unknownKeyID = "77777777-7777-7777-7777-777777777777"
		const cacheUpdateMinInterval = time.Second * 1

		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{CacheUpdateMinInterval: cacheUpdateMinInterval})

		doGetPublicKeyByUnknownID := func(callsNum int) {
			t.Helper()
			var wg sync.WaitGroup
			wg.Add(callsNum)
			for i := 0; i < callsNum; i++ {
				go func() {
					defer wg.Done()
					pubKey, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, unknownKeyID)
					require.Error(t, err)
					var jwkErr *jwks.JWKNotFoundError
					require.True(t, errors.As(err, &jwkErr))
					require.Equal(t, issuerConfigServer.URL, jwkErr.IssuerURL)
					require.Equal(t, unknownKeyID, jwkErr.KeyID)
					require.Nil(t, pubKey)
				}()
			}
			wg.Wait()
		}

		doGetPublicKeyByUnknownID(10)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		time.Sleep(cacheUpdateMinInterval * 2)

		doGetPublicKeyByUnknownID(10)
		require.EqualValues(t, 2, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 2, jwksHandler.ServedCount())
	})

	t.Run("cache ttl expiration", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const cacheTTL = time.Millisecond * 100
		const cacheUpdateMinInterval = time.Millisecond * 10

		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
			CacheTTL:               cacheTTL,
			CacheUpdateMinInterval: cacheUpdateMinInterval,
		})

		// First request - should fetch from server
		pubKey1, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey1)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Second request immediately - should use cache
		pubKey2, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey2)
		require.Equal(t, pubKey1, pubKey2)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Wait for cache to expire
		time.Sleep(cacheTTL + time.Millisecond*50)

		// Third request after TTL - should fetch from server again
		pubKey3, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey3)
		require.EqualValues(t, 2, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 2, jwksHandler.ServedCount())
	})

	t.Run("cache ttl with default value", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		// Create client without specifying TTL - should use default
		cachingClient := jwks.NewCachingClient()

		// First request - should fetch from server
		pubKey, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Second request - should use cache (default TTL is 1 hour, so cache is fresh)
		pubKey2, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey2)
		require.Equal(t, pubKey, pubKey2)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())
	})

	t.Run("invalidate cache respects ttl", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const cacheTTL = time.Millisecond * 100
		const cacheUpdateMinInterval = time.Millisecond * 10

		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
			CacheTTL:               cacheTTL,
			CacheUpdateMinInterval: cacheUpdateMinInterval,
		})

		// Populate cache
		err := cachingClient.InvalidateCacheIfNeeded(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Try to invalidate immediately - should not refetch due to cacheUpdateMinInterval
		err = cachingClient.InvalidateCacheIfNeeded(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Wait for cache to expire
		time.Sleep(cacheTTL + time.Millisecond*50)

		// Invalidate after TTL - should refetch
		err = cachingClient.InvalidateCacheIfNeeded(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.EqualValues(t, 2, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 2, jwksHandler.ServedCount())
	})
}
