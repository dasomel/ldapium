package machineauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Transport limits of D15.
const (
	FetchTimeout = 5 * time.Second
	MaxBodyBytes = 1 << 20 // 1 MiB
	MaxJWKSKeys  = 20
)

// Fetcher retrieves one document (discovery or JWKS). It is the injection
// point for tests; the production implementation is NewHTTPFetcher.
type Fetcher interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// NewHTTPFetcher returns the dedicated client of D15: 5 s timeout, no
// redirects, TLS 1.2 or newer, 1 MiB body cap. A response above the cap, a
// non-200 status or a redirect is an error, never a truncated success.
func NewHTTPFetcher() Fetcher {
	return &httpFetcher{timeout: FetchTimeout, client: &http.Client{
		Timeout: FetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			Proxy:           http.ProxyFromEnvironment,
		},
	}}
}

type httpFetcher struct {
	client  *http.Client
	timeout time.Duration
}

var errFetchStatus = errors.New("unexpected status")

func (f *httpFetcher) Fetch(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %d", errFetchStatus, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBodyBytes {
		return nil, errors.New("response exceeds size limit")
	}
	return body, nil
}
