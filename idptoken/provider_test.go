/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptoken_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/acronis/go-appkit/httpclient"
	"github.com/acronis/go-appkit/log"
	"github.com/acronis/go-appkit/testutil"
	jwtgo "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/acronis/go-authkit/idptest"
	"github.com/acronis/go-authkit/idptoken"
	"github.com/acronis/go-authkit/internal/metrics"
	"github.com/acronis/go-authkit/jwt"
)

const (
	expectedUserAgent              = "Token MultiSourceProvider/1.0"
	expectedXRequestID             = "test"
	testClientID                   = "89cadd1f-8649-4531-8b1d-a25de5aa3cd6"
	defaultTestTokenExpirationTime = 2
)

type tTokenResponseBody struct {
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope,omitempty"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
}

type tFailingIDPTokenHandler struct{}

func (h *tFailingIDPTokenHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	rw.WriteHeader(http.StatusInternalServerError)
	response := tTokenResponseBody{
		Error: "server_error",
	}
	encoder := json.NewEncoder(rw)
	err := encoder.Encode(response)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

type tHeaderCheckingIDPTokenHandler struct {
	t *testing.T
}

func (h *tHeaderCheckingIDPTokenHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	require.Equal(h.t, expectedUserAgent, r.Header.Get("User-Agent"))
	require.Equal(h.t, expectedXRequestID, r.Header.Get("X-Request-ID"))
	rw.WriteHeader(http.StatusOK)
	response := tTokenResponseBody{
		AccessToken: "success",
		ExpiresIn:   defaultTestTokenExpirationTime,
		Scope:       "tenants:viewer",
	}
	encoder := json.NewEncoder(rw)
	err := encoder.Encode(response)
	if err != nil {
		http.Error(rw, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

type claimsProviderWithExpiration struct {
	ExpTime time.Duration
}

func (d *claimsProviderWithExpiration) Provide(_ *http.Request) (jwt.Claims, error) {
	claims := &jwt.DefaultClaims{
		// nolint:staticcheck // StandardClaims are used here for test purposes
		RegisteredClaims: jwtgo.RegisteredClaims{
			ID:       uuid.NewString(),
			IssuedAt: jwtgo.NewNumericDate(time.Now().UTC()),
		},
		Scope: []jwt.AccessPolicy{
			{
				TenantID:   "1",
				TenantUUID: uuid.NewString(),
				Role:       "tenant:viewer",
			},
		},
	}

	if d.ExpTime <= 0 {
		d.ExpTime = 24 * time.Hour
	}
	claims.ExpiresAt = jwtgo.NewNumericDate(time.Now().UTC().Add(d.ExpTime))

	return claims, nil
}

// ProviderWithCacheSuite tests provider functionality with caching.
type ProviderWithCacheSuite struct {
	suite.Suite
	httpClient *http.Client
	logger     log.FieldLogger
}

func TestProviderWithCacheSuite(t *testing.T) {
	suite.Run(t, new(ProviderWithCacheSuite))
}

func (s *ProviderWithCacheSuite) SetupSuite() {
	tr, _ := httpclient.NewRetryableRoundTripperWithOpts(
		http.DefaultTransport, httpclient.RetryableRoundTripperOpts{MaxRetryAttempts: 3},
	)
	s.httpClient = &http.Client{Transport: tr}
	s.logger = log.NewDisabledLogger()
}

func (s *ProviderWithCacheSuite) TestCustomHeaders() {
	t := s.T()
	server := idptest.NewHTTPServer(
		idptest.WithHTTPTokenHandler(&tHeaderCheckingIDPTokenHandler{t}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	credentials := []idptoken.Source{
		{
			ClientID:     testClientID,
			ClientSecret: "DAGztV5L2hMZyECzer6SXS",
			URL:          server.URL(),
		},
	}
	opts := idptoken.ProviderOpts{
		Logger:           s.logger,
		MinRefreshPeriod: 1 * time.Second,
		CustomHeaders:    map[string]string{"User-Agent": expectedUserAgent},
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
	go provider.RefreshTokensPeriodically(context.Background())
	_, tokenErr := provider.GetTokenWithHeaders(
		context.Background(), testClientID, server.URL(),
		map[string]string{"X-Request-ID": expectedXRequestID}, "tenants:read",
	)
	s.Require().NoError(tokenErr)
}

func (s *ProviderWithCacheSuite) TestGetToken() {
	const tokenTTL = 2 * time.Second

	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: tokenTTL}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	credentials := []idptoken.Source{
		{
			ClientID:     testClientID,
			ClientSecret: "DAGztV5L2hMZyECzer6SXS",
			URL:          server.URL(),
		},
	}
	opts := idptoken.ProviderOpts{
		Logger:           s.logger,
		MinRefreshPeriod: 1 * time.Second,
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
	go provider.RefreshTokensPeriodically(context.Background())
	cachedToken, tokenErr := provider.GetToken(
		context.Background(), testClientID, server.URL(), "tenants:read",
	)
	s.Require().NoError(tokenErr)

	newToken, newTokenErr := provider.GetToken(
		context.Background(), testClientID, server.URL(), "tenants:read",
	)
	s.Require().NoError(newTokenErr)
	s.Require().Equal(cachedToken, newToken, "token was not cached")
	time.Sleep(tokenTTL * 2)

	reissuedToken, reissuedTokenErr := provider.GetToken(
		context.Background(), testClientID, server.URL(), "tenants:read",
	)
	s.Require().NoError(reissuedTokenErr)
	s.Require().NotEqual(reissuedToken, cachedToken, "token was not re-issued")
}

func (s *ProviderWithCacheSuite) TestAutomaticRefresh() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	credentials := []idptoken.Source{
		{
			ClientID:     testClientID,
			ClientSecret: "DAGztV5L2hMZyECzer6SXS",
			URL:          server.URL(),
		},
	}
	opts := idptoken.ProviderOpts{
		Logger:           s.logger,
		MinRefreshPeriod: 1 * time.Second,
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
	go provider.RefreshTokensPeriodically(context.Background())

	tokenOld, tokenErr := provider.GetToken(
		context.Background(), testClientID, server.URL(), "tenants:read",
	)
	s.Require().NoError(tokenErr)
	time.Sleep(3 * time.Second)
	token, refreshErr := provider.GetToken(
		context.Background(), testClientID, server.URL(), "tenants:read",
	)
	s.Require().NoError(refreshErr)
	s.Require().NotEqual(token, tokenOld, "token should have already been refreshed")
}

func (s *ProviderWithCacheSuite) TestInvalidate() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	credentials := []idptoken.Source{
		{
			ClientID:     testClientID,
			ClientSecret: "DAGztV5L2hMZyECzer6SXS",
			URL:          server.URL(),
		},
	}
	opts := idptoken.ProviderOpts{
		Logger:           s.logger,
		MinRefreshPeriod: 10 * time.Second,
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
	go provider.RefreshTokensPeriodically(context.Background())

	tokenOld, tokenErr := provider.GetToken(
		context.Background(), testClientID, server.URL(), "tenants:read",
	)
	s.Require().NoError(tokenErr)
	provider.Invalidate()
	time.Sleep(1 * time.Second)
	token, refreshErr := provider.GetToken(
		context.Background(), testClientID, server.URL(), "tenants:read",
	)
	s.Require().NoError(refreshErr)
	s.Require().NotEqual(token, tokenOld, "token should have already been refreshed")
}

func (s *ProviderWithCacheSuite) TestFailingIDPEndpoint() {
	server := idptest.NewHTTPServer(idptest.WithHTTPTokenHandler(&tFailingIDPTokenHandler{}))
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	credentials := []idptoken.Source{
		{
			ClientID:     testClientID,
			ClientSecret: "DAGztV5L2hMZyECzer6SXS",
			URL:          server.URL(),
		},
		{
			ClientID:     testClientID,
			ClientSecret: "DAGztV5L2hMZyECzer6SXS",
			URL:          server.URL() + "/weird",
		},
	}
	opts := idptoken.ProviderOpts{
		Logger:           s.logger,
		MinRefreshPeriod: 1 * time.Second,
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
	go provider.RefreshTokensPeriodically(context.Background())
	_, tokenErr := provider.GetToken(
		context.Background(), testClientID, server.URL(), "tenants:read",
	)
	s.Require().Error(tokenErr)
	labels := prometheus.Labels{
		metrics.HTTPClientRequestLabelMethod:     http.MethodPost,
		metrics.HTTPClientRequestLabelURL:        server.URL() + idptest.TokenEndpointPath,
		metrics.HTTPClientRequestLabelStatusCode: "500",
		metrics.HTTPClientRequestLabelError:      "unexpected_status_code",
	}
	promMetrics := metrics.GetPrometheusMetrics("", metrics.SourceTokenProvider)
	hist := promMetrics.HTTPClientRequestDuration.With(labels).(prometheus.Histogram)
	testutil.AssertSamplesCountInHistogram(s.T(), hist, 1)
}

func (s *ProviderWithCacheSuite) TestMetrics() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	credentials := []idptoken.Source{
		{
			ClientID:     testClientID,
			ClientSecret: "DAGztV5L2hMZyECzer6SXS",
			URL:          server.URL(),
		},
	}
	opts := idptoken.ProviderOpts{
		Logger:           s.logger,
		MinRefreshPeriod: 1 * time.Second,
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
	go provider.RefreshTokensPeriodically(context.Background())
	_, tokenErr := provider.GetToken(context.Background(), testClientID, server.URL(), "tenants:read")
	s.Require().NoError(tokenErr)
	labels := prometheus.Labels{
		metrics.HTTPClientRequestLabelMethod:     http.MethodPost,
		metrics.HTTPClientRequestLabelURL:        server.URL() + idptest.TokenEndpointPath,
		metrics.HTTPClientRequestLabelStatusCode: "200",
		metrics.HTTPClientRequestLabelError:      "",
	}
	promMetrics := metrics.GetPrometheusMetrics("", metrics.SourceTokenProvider)
	hist := promMetrics.HTTPClientRequestDuration.With(labels).(prometheus.Histogram)
	testutil.AssertSamplesCountInHistogram(s.T(), hist, 1)
}

func (s *ProviderWithCacheSuite) TestMultipleSources() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	server2 := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
		idptest.WithHTTPAddress(":0"), // Use dynamic port
	)
	s.Require().NoError(server2.StartAndWaitForReady(time.Second))
	defer func() { _ = server2.Shutdown(context.Background()) }()

	credentials := []idptoken.Source{
		{
			ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXS", URL: server.URL(),
		},
		{
			ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXs", URL: server2.URL(),
		},
	}
	opts := idptoken.ProviderOpts{
		Logger:           s.logger,
		MinRefreshPeriod: 1 * time.Second,
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)
	go provider.RefreshTokensPeriodically(context.Background())
	_, tokenErr := provider.GetToken(
		context.Background(), testClientID, server.URL(), "tenants:read",
	)
	s.Require().NoError(tokenErr)

	_, tokenErr = provider.GetToken(
		context.Background(), testClientID, server2.URL(), "tenants:read",
	)
	s.Require().NoError(tokenErr)
}

func (s *ProviderWithCacheSuite) TestRegisterSource() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	server2 := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
		idptest.WithHTTPAddress(":0"), // Use dynamic port
	)
	s.Require().NoError(server2.StartAndWaitForReady(time.Second))
	defer func() { _ = server2.Shutdown(context.Background()) }()

	credentials := []idptoken.Source{
		{
			ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXS", URL: server.URL(),
		},
		{
			ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXs", URL: server2.URL(),
		},
	}
	opts := idptoken.ProviderOpts{
		Logger:           s.logger,
		MinRefreshPeriod: 1 * time.Second,
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials[:1], opts)
	go provider.RefreshTokensPeriodically(context.Background())
	provider.RegisterSource(credentials[1])
	_, tokenErr := provider.GetToken(
		context.Background(), testClientID, server2.URL(), "tenants:read",
	)
	s.Require().NoError(tokenErr)
}

func (s *ProviderWithCacheSuite) TestSingleSourceProvider() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	credentials := idptoken.Source{
		ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXS", URL: server.URL(),
	}
	opts := idptoken.ProviderOpts{
		Logger:           s.logger,
		MinRefreshPeriod: 1 * time.Second,
	}
	provider := idptoken.NewProviderWithOpts(credentials, opts)
	go provider.RefreshTokensPeriodically(context.Background())
	_, tokenErr := provider.GetToken(context.Background(), "tenants:read")
	s.Require().NoError(tokenErr)
}

func (s *ProviderWithCacheSuite) TestStartWithNoSourcesAndRegisterLater() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	credentials := idptoken.Source{
		ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXS", URL: server.URL(),
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(nil, idptoken.ProviderOpts{HTTPClient: s.httpClient})
	go provider.RefreshTokensPeriodically(context.Background())
	provider.RegisterSource(credentials)
	_, tokenErr := provider.GetToken(
		context.Background(), testClientID, server.URL(), "tenants:read",
	)
	s.Require().NoError(tokenErr)
}

func (s *ProviderWithCacheSuite) TestRegisterSourceTwice() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 2 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	credentials := idptoken.Source{
		ClientID: testClientID, ClientSecret: "DAGztV5L2hMZyECzer6SXS", URL: server.URL(),
	}
	tokenCache := idptoken.NewInMemoryTokenCache()
	provider := idptoken.NewMultiSourceProviderWithOpts(nil, idptoken.ProviderOpts{
		CustomCacheInstance: tokenCache, HTTPClient: s.httpClient})
	go provider.RefreshTokensPeriodically(context.Background())
	provider.RegisterSource(credentials)
	credentials.ClientSecret = "newsecret"
	provider.RegisterSource(credentials)
	_, tokenErr := provider.GetToken(
		context.Background(), testClientID, server.URL(), "tenants:read",
	)
	s.Require().NoError(tokenErr)
	provider.RegisterSource(credentials)
	s.Require().Equal(1, len(tokenCache.Keys()), "updating with same secret does not reset the cache")
	credentials.ClientSecret = "evennewersecret"
	provider.RegisterSource(credentials)
	s.Require().Equal(0, len(tokenCache.Keys()), "updating with a new secret does reset the cache")
}

// ProviderConcurrencySuite tests provider concurrency behavior.
type ProviderConcurrencySuite struct {
	suite.Suite
}

func TestProviderConcurrencySuite(t *testing.T) {
	suite.Run(t, new(ProviderConcurrencySuite))
}

func (s *ProviderConcurrencySuite) TestConcurrentGetTokenCallsWithSameParameters() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	provider := idptoken.NewProvider(idptoken.Source{
		ClientID:     testClientID,
		ClientSecret: uuid.NewString(),
		URL:          server.URL(),
	})

	const numGoroutines = 100
	var wg sync.WaitGroup
	tokens := make([]string, numGoroutines)
	errors := make([]error, numGoroutines)

	// All goroutines request the same token simultaneously
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			token, err := provider.GetToken(context.Background(), testClientID, server.URL(), "tenants:read")
			tokens[idx] = token
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// All should succeed
	for i := 0; i < numGoroutines; i++ {
		s.Require().NoError(errors[i], "goroutine %d failed", i)
		s.Require().NotEmpty(tokens[i], "goroutine %d got empty token", i)
	}

	// All should get the same token (singleflight should deduplicate)
	firstToken := tokens[0]
	for i := 1; i < numGoroutines; i++ {
		s.Require().Equal(firstToken, tokens[i], "token mismatch at index %d", i)
	}
}

func (s *ProviderConcurrencySuite) TestConcurrentGetTokenCallsWithDifferentParameters() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	provider := idptoken.NewProvider(idptoken.Source{
		ClientID:     testClientID,
		ClientSecret: uuid.NewString(),
		URL:          server.URL(),
	})

	scopes := []string{"scope1", "scope2", "scope3", "scope4", "scope5"}
	const goroutinesPerScope = 20
	var wg sync.WaitGroup
	tokens := make(map[string][]string)
	var tokensMu sync.Mutex
	errors := make([]error, 0)
	var errorsMu sync.Mutex

	// Multiple goroutines request different scopes simultaneously
	for _, scope := range scopes {
		for i := 0; i < goroutinesPerScope; i++ {
			wg.Add(1)
			go func(s string) {
				defer wg.Done()
				token, err := provider.GetToken(context.Background(), testClientID, server.URL(), s)
				if err != nil {
					errorsMu.Lock()
					errors = append(errors, err)
					errorsMu.Unlock()
					return
				}
				tokensMu.Lock()
				tokens[s] = append(tokens[s], token)
				tokensMu.Unlock()
			}(scope)
		}
	}

	wg.Wait()

	// All should succeed
	s.Require().Empty(errors, "some goroutines failed")
	s.Require().Equal(len(scopes), len(tokens), "not all scopes were requested")

	// Tokens for the same scope should be identical
	for scope, scopeTokens := range tokens {
		s.Require().Equal(goroutinesPerScope, len(scopeTokens), "missing tokens for scope %s", scope)
		firstToken := scopeTokens[0]
		for i, token := range scopeTokens {
			s.Require().Equal(firstToken, token, "token mismatch for scope %s at index %d", scope, i)
		}
	}
}

func (s *ProviderConcurrencySuite) TestConcurrentRegisterSourceCalls() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	provider := idptoken.NewMultiSourceProvider(nil)

	const numGoroutines = 50
	var wg sync.WaitGroup

	// Multiple goroutines register sources simultaneously
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			source := idptoken.Source{
				ClientID:     fmt.Sprintf("client-%d", idx),
				ClientSecret: fmt.Sprintf("secret-%d", idx),
				URL:          server.URL(),
			}
			provider.RegisterSource(source)
		}(i)
	}

	wg.Wait()

	// All sources should be registered successfully
	// Try to get tokens for all registered sources
	for i := 0; i < numGoroutines; i++ {
		clientID := fmt.Sprintf("client-%d", i)
		_, err := provider.GetToken(context.Background(), clientID, server.URL(), "scope")
		s.Require().NoError(err, "failed to get token for client-%d", i)
	}
}

func (s *ProviderConcurrencySuite) TestConcurrentGetTokenAndInvalidate() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	provider := idptoken.NewProvider(idptoken.Source{
		ClientID:     testClientID,
		ClientSecret: uuid.NewString(),
		URL:          server.URL(),
	})

	const numGoroutines = 50
	var wg sync.WaitGroup
	successCount := int32(0)

	// Some goroutines get tokens while others invalidate
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%5 == 0 {
				provider.Invalidate()
			}
			_, err := provider.GetToken(context.Background(), testClientID, server.URL(), "tenants:read")
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			}
		}(i)
	}

	wg.Wait()

	// All GetToken calls should succeed
	s.Require().Equal(int(successCount), numGoroutines, "some GetToken calls failed")
}

func (s *ProviderConcurrencySuite) TestConcurrentGetTokenWithRefreshLoop() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 3 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	provider := idptoken.NewProviderWithOpts(idptoken.Source{
		ClientID:     testClientID,
		ClientSecret: uuid.NewString(),
		URL:          server.URL(),
	}, idptoken.ProviderOpts{
		MinRefreshPeriod: 500 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go provider.RefreshTokensPeriodically(ctx)

	const numGoroutines = 30
	const duration = 5 * time.Second
	var wg sync.WaitGroup
	stopTime := time.Now().Add(duration)

	// Continuously request tokens while refresh loop is running
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for time.Now().Before(stopTime) {
				_, err := provider.GetToken(context.Background(), testClientID, server.URL(), "tenants:read")
				if err != nil {
					s.T().Logf("goroutine %d got error: %v", idx, err)
				}
				time.Sleep(100 * time.Millisecond)
			}
		}(i)
	}

	wg.Wait()
}

func (s *ProviderConcurrencySuite) TestConcurrentGetTokenWithHeaders() {
	server := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
	)
	s.Require().NoError(server.StartAndWaitForReady(time.Second))
	defer func() { _ = server.Shutdown(context.Background()) }()

	provider := idptoken.NewProvider(idptoken.Source{
		ClientID:     testClientID,
		ClientSecret: uuid.NewString(),
		URL:          server.URL(),
	})

	const numGoroutines = 50
	var wg sync.WaitGroup
	errors := make([]error, numGoroutines)

	// Multiple goroutines request tokens with different headers
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			headers := map[string]string{
				"X-Request-ID": fmt.Sprintf("request-%d", idx),
			}
			_, err := provider.GetTokenWithHeaders(context.Background(), headers, "tenants:read")
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// All should succeed
	for i := 0; i < numGoroutines; i++ {
		s.Require().NoError(errors[i], "goroutine %d failed", i)
	}
}

func (s *ProviderConcurrencySuite) TestConcurrentCacheOperations() {
	cache := idptoken.NewInMemoryTokenCache()

	const numGoroutines = 100
	var wg sync.WaitGroup

	// Mix of Put, Get, Delete, Keys, GetAll operations
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			key := fmt.Sprintf("key-%d", idx%10) // Reuse some keys

			// Put
			details := &idptoken.TokenDetails{}
			cache.Put(key, details)

			// Get
			_ = cache.Get(key)

			// Keys
			_ = cache.Keys()

			// GetAll
			_ = cache.GetAll()

			// Delete some
			if idx%3 == 0 {
				cache.Delete(key)
			}
		}(i)
	}

	wg.Wait()
}

func (s *ProviderConcurrencySuite) TestConcurrentMultiSourceAccess() {
	server1 := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
	)
	s.Require().NoError(server1.StartAndWaitForReady(time.Second))
	defer func() { _ = server1.Shutdown(context.Background()) }()

	server2 := idptest.NewHTTPServer(
		idptest.WithHTTPClaimsProvider(&claimsProviderWithExpiration{ExpTime: 10 * time.Second}),
		idptest.WithHTTPAddress(":0"), // Use dynamic port
	)
	s.Require().NoError(server2.StartAndWaitForReady(time.Second))
	defer func() { _ = server2.Shutdown(context.Background()) }()

	provider := idptoken.NewMultiSourceProvider([]idptoken.Source{
		{
			ClientID:     "client1",
			ClientSecret: uuid.NewString(),
			URL:          server1.URL(),
		},
		{
			ClientID:     "client2",
			ClientSecret: uuid.NewString(),
			URL:          server2.URL(),
		},
	})

	const numGoroutines = 100
	var wg sync.WaitGroup
	errors := make([]error, numGoroutines)

	// Goroutines randomly access different sources
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				_, err := provider.GetToken(context.Background(), "client1", server1.URL(), "scope1")
				errors[idx] = err
			} else {
				_, err := provider.GetToken(context.Background(), "client2", server2.URL(), "scope2")
				errors[idx] = err
			}
		}(i)
	}

	wg.Wait()

	// All should succeed
	for i := 0; i < numGoroutines; i++ {
		s.Require().NoError(errors[i], "goroutine %d failed", i)
	}
}

// ProviderErrorsSuite tests provider error handling.
type ProviderErrorsSuite struct {
	suite.Suite
}

func TestProviderErrorsSuite(t *testing.T) {
	suite.Run(t, new(ProviderErrorsSuite))
}

func (s *ProviderErrorsSuite) TestOpenIDConfigurationReturns503() {
	const retryAfterValue = "120"

	// Create a test server that returns 503 for OpenID configuration endpoint
	testServer := http.NewServeMux()
	testServer.HandleFunc(idptest.OpenIDConfigurationPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", retryAfterValue)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	server := &http.Server{Addr: "127.0.0.1:0", Handler: testServer}
	listener, err := net.Listen("tcp", server.Addr)
	s.Require().NoError(err)
	defer func() { _ = listener.Close() }()

	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Shutdown(context.Background()) }()

	serverURL := fmt.Sprintf("http://%s", listener.Addr().String())

	credentials := []idptoken.Source{
		{
			ClientID:     testClientID,
			ClientSecret: "test-secret",
			URL:          serverURL,
		},
	}
	// Use a custom HTTP client with minimal timeout and no retries
	httpClient := &http.Client{Timeout: 2 * time.Second}
	opts := idptoken.ProviderOpts{
		HTTPClient: httpClient,
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)

	_, err = provider.GetToken(context.Background(), testClientID, serverURL)
	var svcUnavailableErr *idptoken.ServiceUnavailableError
	s.Require().ErrorAs(err, &svcUnavailableErr)
	s.Require().Equal(retryAfterValue, svcUnavailableErr.RetryAfter)
}

func (s *ProviderErrorsSuite) TestOpenIDConfigurationReturns429() {
	const retryAfterValue = "120"

	// Create a test server that returns 429 for OpenID configuration endpoint
	testServer := http.NewServeMux()
	testServer.HandleFunc(idptest.OpenIDConfigurationPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", retryAfterValue)
		w.WriteHeader(http.StatusTooManyRequests)
	})
	server := &http.Server{Addr: "127.0.0.1:0", Handler: testServer}
	listener, err := net.Listen("tcp", server.Addr)
	s.Require().NoError(err)
	defer func() { _ = listener.Close() }()

	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Shutdown(context.Background()) }()

	serverURL := fmt.Sprintf("http://%s", listener.Addr().String())

	credentials := []idptoken.Source{
		{
			ClientID:     testClientID,
			ClientSecret: "test-secret",
			URL:          serverURL,
		},
	}
	// Use a custom HTTP client with minimal timeout and no retries
	httpClient := &http.Client{Timeout: 2 * time.Second}
	opts := idptoken.ProviderOpts{
		HTTPClient: httpClient,
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)

	_, err = provider.GetToken(context.Background(), testClientID, serverURL)
	var throttledErr *idptoken.ThrottledError
	s.Require().ErrorAs(err, &throttledErr)
	s.Require().Equal(retryAfterValue, throttledErr.RetryAfter)
}

func (s *ProviderErrorsSuite) TestTokenEndpointReturns503() {
	const retryAfterValue = "120"

	// Create a test server that returns 503 for token endpoint
	testServer := http.NewServeMux()
	// OpenID configuration needs to be served to get the token URL
	testServer.HandleFunc(idptest.OpenIDConfigurationPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{
			"token_endpoint": fmt.Sprintf("http://%s%s", r.Host, idptest.TokenEndpointPath),
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	testServer.HandleFunc(idptest.TokenEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", retryAfterValue)
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	server := &http.Server{Addr: "127.0.0.1:0", Handler: testServer}
	listener, err := net.Listen("tcp", server.Addr)
	s.Require().NoError(err)
	defer func() { _ = listener.Close() }()

	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Shutdown(context.Background()) }()

	serverURL := fmt.Sprintf("http://%s", listener.Addr().String())

	credentials := []idptoken.Source{
		{
			ClientID:     testClientID,
			ClientSecret: "test-secret",
			URL:          serverURL,
		},
	}
	// Use a custom HTTP client with minimal timeout and no retries
	httpClient := &http.Client{Timeout: 2 * time.Second}
	opts := idptoken.ProviderOpts{
		HTTPClient: httpClient,
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)

	_, err = provider.GetToken(context.Background(), testClientID, serverURL)
	var svcUnavailableErr *idptoken.ServiceUnavailableError
	s.Require().ErrorAs(err, &svcUnavailableErr)
	s.Require().Equal(retryAfterValue, svcUnavailableErr.RetryAfter)
}

func (s *ProviderErrorsSuite) TestTokenEndpointReturns429() {
	const retryAfterValue = "120"

	// Create a test server that returns 429 for token endpoint
	testServer := http.NewServeMux()
	// OpenID configuration needs to be served to get the token URL
	testServer.HandleFunc(idptest.OpenIDConfigurationPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{
			"token_endpoint": fmt.Sprintf("http://%s%s", r.Host, idptest.TokenEndpointPath),
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	testServer.HandleFunc(idptest.TokenEndpointPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", retryAfterValue)
		w.WriteHeader(http.StatusTooManyRequests)
	})
	server := &http.Server{Addr: "127.0.0.1:0", Handler: testServer}
	listener, err := net.Listen("tcp", server.Addr)
	s.Require().NoError(err)
	defer func() { _ = listener.Close() }()

	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Shutdown(context.Background()) }()

	serverURL := fmt.Sprintf("http://%s", listener.Addr().String())

	credentials := []idptoken.Source{
		{
			ClientID:     testClientID,
			ClientSecret: "test-secret",
			URL:          serverURL,
		},
	}
	// Use a custom HTTP client with minimal timeout and no retries
	httpClient := &http.Client{Timeout: 2 * time.Second}
	opts := idptoken.ProviderOpts{
		HTTPClient: httpClient,
	}
	provider := idptoken.NewMultiSourceProviderWithOpts(credentials, opts)

	_, err = provider.GetToken(context.Background(), testClientID, serverURL)
	var throttledErr *idptoken.ThrottledError
	s.Require().ErrorAs(err, &throttledErr)
	s.Require().Equal(retryAfterValue, throttledErr.RetryAfter)
}
