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
}

func TestCachingClient_GetRSAPublicKey_TTLExpiration(t *testing.T) {
	jwksHandler := &idptest.JWKSHandler{}
	jwksServer := httptest.NewServer(jwksHandler)
	defer jwksServer.Close()
	issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
	issuerConfigServer := httptest.NewServer(issuerConfigHandler)
	defer issuerConfigServer.Close()

	const ttl = 50 * time.Millisecond
	const minInterval = 10 * time.Millisecond
	client := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
		CacheUpdateMinInterval: minInterval,
		CacheTTL:               ttl,
	})

	ctx := context.Background()
	pubKey, err := client.GetRSAPublicKey(ctx, issuerConfigServer.URL, idptest.TestKeyID)
	require.NoError(t, err)
	require.NotNil(t, pubKey)
	require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
	require.EqualValues(t, 1, jwksHandler.ServedCount())

	// Cache hit within TTL should not trigger additional upstream requests.
	pubKeyCached, err := client.GetRSAPublicKey(ctx, issuerConfigServer.URL, idptest.TestKeyID)
	require.NoError(t, err)
	require.NotNil(t, pubKeyCached)
	require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
	require.EqualValues(t, 1, jwksHandler.ServedCount())

	time.Sleep(ttl + 20*time.Millisecond)

	pubKeyAfterTTL, err := client.GetRSAPublicKey(ctx, issuerConfigServer.URL, idptest.TestKeyID)
	require.NoError(t, err)
	require.NotNil(t, pubKeyAfterTTL)
	require.EqualValues(t, 2, issuerConfigHandler.ServedCount())
	require.EqualValues(t, 2, jwksHandler.ServedCount())
}

func TestCachingClient_GetRSAPublicKey_MissingKeyTTL(t *testing.T) {
	jwksHandler := &idptest.JWKSHandler{}
	jwksServer := httptest.NewServer(jwksHandler)
	defer jwksServer.Close()
	issuerConfigHandler := &idptest.OpenIDConfigurationHandler{JWKSURL: jwksServer.URL}
	issuerConfigServer := httptest.NewServer(issuerConfigHandler)
	defer issuerConfigServer.Close()

	const unknownKeyID = "77777777-7777-7777-7777-777777777777"
	const ttl = 50 * time.Millisecond
	const minInterval = 200 * time.Millisecond
	client := jwks.NewCachingClientWithOpts(jwks.CachingClientOpts{
		CacheUpdateMinInterval: minInterval,
		CacheTTL:               ttl,
	})

	ctx := context.Background()
	assertNotFound := func(err error) {
		var jwkErr *jwks.JWKNotFoundError
		require.Error(t, err)
		require.ErrorAs(t, err, &jwkErr)
		require.Equal(t, issuerConfigServer.URL, jwkErr.IssuerURL)
		require.Equal(t, unknownKeyID, jwkErr.KeyID)
	}

	_, err := client.GetRSAPublicKey(ctx, issuerConfigServer.URL, unknownKeyID)
	assertNotFound(err)
	require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
	require.EqualValues(t, 1, jwksHandler.ServedCount())

	_, err = client.GetRSAPublicKey(ctx, issuerConfigServer.URL, unknownKeyID)
	assertNotFound(err)
	require.EqualValues(t, 1, issuerConfigHandler.ServedCount())
	require.EqualValues(t, 1, jwksHandler.ServedCount())

	time.Sleep(ttl + 20*time.Millisecond)

	_, err = client.GetRSAPublicKey(ctx, issuerConfigServer.URL, unknownKeyID)
	assertNotFound(err)
	require.EqualValues(t, 2, issuerConfigHandler.ServedCount())
	require.EqualValues(t, 2, jwksHandler.ServedCount())
}
