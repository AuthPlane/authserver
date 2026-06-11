// Package hcvault implements key storage and data encryption using
// HashiCorp Vault Transit. Signing keys never leave Vault — signing
// and encryption are delegated over the Vault HTTP API.
//
// A single Client is shared between the KeyStore (JWT signing) and
// DataEncryptor (data encryption) when both target the same Vault
// server and Transit mount.
package hcvault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/authplane/authserver/internal/observability"
)

// maxVaultResponseLen caps the response body read from Vault to 1 MiB.
// This prevents a compromised/malicious Vault endpoint from causing OOM.
const maxVaultResponseLen = 1 << 20

// Client is a minimal Vault HTTP client that supports token and AppRole auth.
// It handles background token renewal when using AppRole.
type Client struct {
	httpClient *http.Client
	addr       string // e.g. "https://vault.example.com:8200"
	mount      string // transit mount path, e.g. "transit"

	mu    sync.RWMutex
	token string

	// AppRole fields (nil if using static token).
	appRole *AppRoleAuth

	logger *slog.Logger
	tracer trace.Tracer

	// cancel stops the background renewal goroutine.
	cancel context.CancelFunc
}

// AppRoleAuth holds AppRole authentication details.
type AppRoleAuth struct {
	RoleID   string
	SecretID string
	Mount    string // default "approle"
}

// ClientConfig configures the Vault client.
type ClientConfig struct {
	Address string
	Token   string // static token (mutually exclusive with AppRole)
	Mount   string // transit secret engine mount, default "transit"
	AppRole *AppRoleAuth
	Timeout time.Duration // HTTP client timeout, default 10s
}

// NewClient creates a Vault Transit client.
// If AppRole is configured, it performs an initial login and starts a background
// renewal goroutine. Call Close() to stop renewal.
func NewClient(ctx context.Context, cfg ClientConfig, obs *observability.Provider) (*Client, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault address is required")
	}
	if cfg.Token == "" && cfg.AppRole == nil {
		return nil, fmt.Errorf("vault token or approle config is required")
	}
	if cfg.Mount == "" {
		cfg.Mount = "transit"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.AppRole != nil && cfg.AppRole.Mount == "" {
		cfg.AppRole.Mount = "approle"
	}

	renewCtx, cancel := context.WithCancel(context.Background())

	c := &Client{
		httpClient: &http.Client{Timeout: cfg.Timeout},
		addr:       cfg.Address,
		mount:      cfg.Mount,
		token:      cfg.Token,
		appRole:    cfg.AppRole,
		logger:     obs.Logger.With("component", "vault-client"),
		tracer:     obs.Tracer,
		cancel:     cancel,
	}

	// If using AppRole, perform initial login.
	if cfg.AppRole != nil {
		leaseDuration, err := c.appRoleLogin(ctx)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("vault approle login: %w", err)
		}
		c.logger.InfoContext(ctx, "vault approle login successful",
			"lease_duration_s", leaseDuration,
		)
		// Start background renewal at half the lease duration.
		go c.renewLoop(renewCtx, leaseDuration)
	}

	return c, nil
}

// Close stops the background token renewal goroutine.
func (c *Client) Close() {
	if c.cancel != nil {
		c.cancel()
	}
}

// Address returns the Vault server address.
func (c *Client) Address() string { return c.addr }

// Mount returns the Transit mount path.
func (c *Client) Mount() string { return c.mount }

// appRoleLogin performs an AppRole login and stores the resulting token.
// Returns the lease duration in seconds.
func (c *Client) appRoleLogin(ctx context.Context) (int, error) {
	ctx, span := c.tracer.Start(ctx, "VaultClient.AppRoleLogin")
	defer span.End()

	body := map[string]string{
		"role_id":   c.appRole.RoleID,
		"secret_id": c.appRole.SecretID,
	}
	path := fmt.Sprintf("/v1/auth/%s/login", c.appRole.Mount)

	resp, err := c.rawRequest(ctx, "POST", path, body, "")
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("approle login request: %w", err)
	}

	var loginResp struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(resp, &loginResp); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, fmt.Errorf("parse login response: %w", err)
	}
	if loginResp.Auth.ClientToken == "" {
		err := fmt.Errorf("empty client_token in approle login response")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return 0, err
	}

	c.mu.Lock()
	c.token = loginResp.Auth.ClientToken
	c.mu.Unlock()

	return loginResp.Auth.LeaseDuration, nil
}

// renewLoop re-authenticates at half the lease duration.
func (c *Client) renewLoop(ctx context.Context, leaseDurationSecs int) {
	defer func() {
		if r := recover(); r != nil {
			c.logger.ErrorContext(ctx, "panic in vault renewal goroutine", "panic", r)
		}
	}()

	renewInterval := time.Duration(leaseDurationSecs) * time.Second / 2
	if renewInterval < 10*time.Second {
		renewInterval = 10 * time.Second
	}
	ticker := time.NewTicker(renewInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newLease, err := c.appRoleLogin(ctx)
			if err != nil {
				c.logger.WarnContext(ctx, "vault token renewal failed", "error", err)
				continue
			}
			c.logger.DebugContext(ctx, "vault token renewed",
				"lease_duration_s", newLease,
			)
			// Adjust interval if lease changed.
			newInterval := time.Duration(newLease) * time.Second / 2
			if newInterval < 10*time.Second {
				newInterval = 10 * time.Second
			}
			if newInterval != renewInterval {
				ticker.Reset(newInterval)
				renewInterval = newInterval
			}
		}
	}
}

// getToken returns the current Vault token (thread-safe).
func (c *Client) getToken() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// Sign calls the Vault Transit sign endpoint.
// digest is base64-encoded, prehashed indicates the input is already hashed.
func (c *Client) Sign(ctx context.Context, keyName, digest, hashAlg string, keyVersion int) (string, error) {
	ctx, span := c.tracer.Start(ctx, "VaultClient.Sign")
	defer span.End()
	span.SetAttributes(
		attribute.String("vault.key_name", keyName),
		attribute.String("vault.hash_algorithm", hashAlg),
		attribute.Int("vault.key_version", keyVersion),
	)

	body := map[string]interface{}{
		"input":          digest,
		"prehashed":      true,
		"hash_algorithm": hashAlg,
	}
	if keyVersion > 0 {
		body["key_version"] = keyVersion
	}

	path := fmt.Sprintf("/v1/%s/sign/%s", c.mount, keyName)
	resp, err := c.request(ctx, "POST", path, body)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("vault sign: %w", err)
	}

	var signResp struct {
		Data struct {
			Signature  string `json:"signature"`
			KeyVersion int    `json:"key_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &signResp); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("parse sign response: %w", err)
	}
	if signResp.Data.Signature == "" {
		err := fmt.Errorf("empty signature in vault response")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	return signResp.Data.Signature, nil
}

// ReadKey reads the public key material from a Transit key.
func (c *Client) ReadKey(ctx context.Context, keyName string) ([]byte, error) {
	ctx, span := c.tracer.Start(ctx, "VaultClient.ReadKey")
	defer span.End()
	span.SetAttributes(attribute.String("vault.key_name", keyName))

	path := fmt.Sprintf("/v1/%s/keys/%s", c.mount, keyName)
	return c.request(ctx, "GET", path, nil)
}

// CreateKey creates a new Transit key.
func (c *Client) CreateKey(ctx context.Context, keyName, keyType string) error {
	ctx, span := c.tracer.Start(ctx, "VaultClient.CreateKey")
	defer span.End()
	span.SetAttributes(
		attribute.String("vault.key_name", keyName),
		attribute.String("vault.key_type", keyType),
	)

	body := map[string]string{"type": keyType}
	path := fmt.Sprintf("/v1/%s/keys/%s", c.mount, keyName)
	_, err := c.request(ctx, "POST", path, body)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("vault create key: %w", err)
	}
	return nil
}

// RotateKey rotates a Transit key to a new version.
func (c *Client) RotateKey(ctx context.Context, keyName string) error {
	ctx, span := c.tracer.Start(ctx, "VaultClient.RotateKey")
	defer span.End()
	span.SetAttributes(attribute.String("vault.key_name", keyName))

	path := fmt.Sprintf("/v1/%s/keys/%s/rotate", c.mount, keyName)
	_, err := c.request(ctx, "POST", path, nil)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("vault rotate key: %w", err)
	}
	return nil
}

// Encrypt calls the Vault Transit encrypt endpoint.
// plaintext and context are base64-encoded by the caller.
func (c *Client) Encrypt(ctx context.Context, keyName, plaintext, derivedContext string) (string, error) {
	ctx, span := c.tracer.Start(ctx, "VaultClient.Encrypt")
	defer span.End()
	span.SetAttributes(attribute.String("vault.key_name", keyName))

	body := map[string]string{
		"plaintext": plaintext,
		"context":   derivedContext,
	}

	path := fmt.Sprintf("/v1/%s/encrypt/%s", c.mount, keyName)
	resp, err := c.request(ctx, "POST", path, body)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("vault encrypt: %w", err)
	}

	var encResp struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &encResp); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("parse encrypt response: %w", err)
	}
	if encResp.Data.Ciphertext == "" {
		err := fmt.Errorf("empty ciphertext in vault response")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	return encResp.Data.Ciphertext, nil
}

// Decrypt calls the Vault Transit decrypt endpoint.
// Returns the base64-encoded plaintext.
func (c *Client) Decrypt(ctx context.Context, keyName, ciphertext, derivedContext string) (string, error) {
	ctx, span := c.tracer.Start(ctx, "VaultClient.Decrypt")
	defer span.End()
	span.SetAttributes(attribute.String("vault.key_name", keyName))

	body := map[string]string{
		"ciphertext": ciphertext,
		"context":    derivedContext,
	}

	path := fmt.Sprintf("/v1/%s/decrypt/%s", c.mount, keyName)
	resp, err := c.request(ctx, "POST", path, body)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("vault decrypt: %w", err)
	}

	var decResp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := json.Unmarshal(resp, &decResp); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", fmt.Errorf("parse decrypt response: %w", err)
	}
	if decResp.Data.Plaintext == "" {
		err := fmt.Errorf("empty plaintext in vault response")
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return "", err
	}

	return decResp.Data.Plaintext, nil
}

// request sends an authenticated request to Vault.
func (c *Client) request(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	return c.rawRequest(ctx, method, path, body, c.getToken())
}

// rawRequest sends a request to Vault with an explicit token.
func (c *Client) rawRequest(ctx context.Context, method, path string, body interface{}, token string) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	url := c.addr + path
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxVaultResponseLen+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(respBody) > maxVaultResponseLen {
		return nil, fmt.Errorf("vault response exceeds max size (%d bytes)", maxVaultResponseLen)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &VaultError{
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
			Path:       path,
		}
	}

	return respBody, nil
}

// VaultError represents a non-2xx response from Vault.
type VaultError struct {
	StatusCode int
	Body       string
	Path       string
}

func (e *VaultError) Error() string {
	body := e.Body
	if len(body) > 200 {
		body = body[:200] + "...(truncated)"
	}
	return fmt.Sprintf("vault %s: status %d: %s", e.Path, e.StatusCode, body)
}
