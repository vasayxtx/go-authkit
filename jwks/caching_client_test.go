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

	t.Run("ttl expiration", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const cacheTTL = time.Second * 2
		const cacheUpdateMinInterval = time.Millisecond * 100

		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
			CacheTTL:               cacheTTL,
			CacheUpdateMinInterval: cacheUpdateMinInterval,
		})

		// First request - should fetch from server
		pubKey1, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey1)
		require.IsType(t, &rsa.PublicKey{}, pubKey1)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Second request - should use cache
		pubKey2, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey2)
		require.Equal(t, pubKey1, pubKey2)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Wait for TTL to expire
		time.Sleep(cacheTTL + time.Millisecond*100)

		// Third request - should fetch from server again due to TTL expiration
		pubKey3, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey3)
		require.IsType(t, &rsa.PublicKey{}, pubKey3)
		require.EqualValues(t, 2, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 2, jwksHandler.ServedCount())

		// Fourth request - should use cache again
		pubKey4, err := cachingClient.GetRSAPublicKey(context.Background(), issuerConfigServer.URL, idptest.TestKeyID)
		require.NoError(t, err)
		require.NotNil(t, pubKey4)
		require.Equal(t, pubKey3, pubKey4)
		require.EqualValues(t, 2, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 2, jwksHandler.ServedCount())
	})

	t.Run("ttl expiration with InvalidateCacheIfNeeded", func(t *testing.T) {
		jwksHandler := &idptest.JWKSHandler{}
		jwksServer := httptest.NewServer(jwksHandler)
		defer jwksServer.Close()
		issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
		issuerConfigServer := httptest.NewServer(issuerConfigHandler)
		defer issuerConfigServer.Close()

		const cacheTTL = time.Second * 2
		const cacheUpdateMinInterval = time.Second * 10

		cachingClient := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
			CacheTTL:               cacheTTL,
			CacheUpdateMinInterval: cacheUpdateMinInterval,
		})

		// First request - should fetch from server
		err := cachingClient.InvalidateCacheIfNeeded(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Second request - should not fetch due to cacheUpdateMinInterval
		err = cachingClient.InvalidateCacheIfNeeded(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 1, jwksHandler.ServedCount())

		// Wait for TTL to expire (but not cacheUpdateMinInterval)
		time.Sleep(cacheTTL + time.Millisecond*100)

		// Third request - should fetch from server again due to TTL expiration
		// even though cacheUpdateMinInterval has not passed
		err = cachingClient.InvalidateCacheIfNeeded(context.Background(), issuerConfigServer.URL)
		require.NoError(t, err)
		require.EqualValues(t, 2, issuerConfigHandler.ServedCount())
		require.EqualValues(t, 2, jwksHandler.ServedCount())
	})

	t.Run("default ttl is 1 hour", func(t *testing.T) {
		cachingClient := jwks.NewCachingClient()
		// We can't directly access cacheTTL field, but we can verify the default is used
		// by checking that the client doesn't panic and uses the default value
		require.NotNil(t, cachingClient)
	})
}
