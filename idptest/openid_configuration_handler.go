/*
Copyright © 2024 Acronis International GmbH.

Released under MIT license.
*/

package idptest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
)

// OpenIDConfigurationHandler is an HTTP handler that responds token's issuer OpenID configuration.
type OpenIDConfigurationHandler struct {
	servedCount                   atomic.Uint64
	JWKSEndpointProvider          func() string
	TokenEndpointProvider         func() string
	IntrospectionEndpointProvider func() string
}

func (h *OpenIDConfigurationHandler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	h.servedCount.Add(1)

	openIDCfg := OpenIDConfigurationResponse{}
	if h.TokenEndpointProvider != nil {
		openIDCfg.TokenEndpoint = h.TokenEndpointProvider()
	}
	if h.IntrospectionEndpointProvider != nil {
		openIDCfg.IntrospectionEndpoint = h.IntrospectionEndpointProvider()
	}
	if h.JWKSEndpointProvider != nil {
		openIDCfg.JWKSURI = h.JWKSEndpointProvider()
	}
	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(openIDCfg); err != nil {
		http.Error(rw, fmt.Sprintf("Error encoding response: %v", err), http.StatusInternalServerError)
		return
	}
}

// ServedCount returns the number of times the handler has been served.
func (h *OpenIDConfigurationHandler) ServedCount() uint64 {
	return h.servedCount.Load()
}

// OpenIDConfigurationResponse is a response for .well-known/openid-configuration endpoint.
type OpenIDConfigurationResponse struct {
	TokenEndpoint         string `json:"token_endpoint"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}
