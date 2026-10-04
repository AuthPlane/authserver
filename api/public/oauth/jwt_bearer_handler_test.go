package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/authplane/authserver/internal/domain"
	"github.com/authplane/authserver/internal/observability"
	"github.com/authplane/authserver/internal/ports/input"
)

const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// capturingJWTBearer records the request the handler built and answers
// with a canned response or error.
type capturingJWTBearer struct {
	got  input.JWTBearerRequest
	resp *input.JWTBearerResponse
	err  error
}

func (f *capturingJWTBearer) GrantJWTBearer(_ context.Context, req input.JWTBearerRequest) (*input.JWTBearerResponse, error) {
	f.got = req
	return f.resp, f.err
}

// postJWTBearer drives handleToken (so the form is parsed and the grant is
// dispatched exactly as in production) with the given form and headers.
func postJWTBearer(t *testing.T, h *oauthHandler, form url.Values, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	form.Set("grant_type", jwtBearerGrantType)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://as.example.com/oauth/token?x=1", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.handleToken(rec, req)
	return rec
}

func decodeJSONBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body %q: %v", rec.Body.String(), err)
	}
	return body
}

func basicAuth(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

// With XAA off the provider is nil. The grant must be refused as
// unsupported_grant_type naming the config key, not dereference nil.
func TestHandleJWTBearer_ProviderNotWired(t *testing.T) {
	h := &oauthHandler{obs: observability.NewNoop()}

	rec := postJWTBearer(t, h, url.Values{"assertion": {"a.b.c"}}, nil)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	body := decodeJSONBody(t, rec)
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error = %v, want unsupported_grant_type", body["error"])
	}
	desc, _ := body["error_description"].(string)
	if !strings.Contains(desc, "xaa.enabled=true") {
		t.Errorf("error_description = %q, want it to name xaa.enabled=true", desc)
	}
}

// Every form field and both client-auth transports must reach the service
// unchanged; the DPoP triple is populated only when a DPoP header is present.
func TestHandleJWTBearer_BuildsServiceRequest(t *testing.T) {
	cases := []struct {
		name    string
		form    url.Values
		headers map[string]string
		want    input.JWTBearerRequest
	}{
		{
			name: "client auth in the form body, no DPoP",
			form: url.Values{
				"assertion":     {"eyJ.assertion.sig"},
				"client_id":     {"client-form"},
				"client_secret": {"secret-form"},
				"scope":         {"read write"},
				"resource":      {"https://api.example.com"},
			},
			want: input.JWTBearerRequest{
				Assertion:    "eyJ.assertion.sig",
				ClientID:     "client-form",
				ClientSecret: "secret-form",
				Scope:        "read write",
				Resource:     "https://api.example.com",
			},
		},
		{
			name: "Basic header wins over the form and DPoP header fills the proof triple",
			form: url.Values{
				"assertion":     {"eyJ.assertion.sig"},
				"client_id":     {"client-form"},
				"client_secret": {"secret-form"},
			},
			headers: map[string]string{
				"Authorization": basicAuth("client-basic", "secret-basic"),
				"DPoP":          "eyJ.proof.sig",
			},
			want: input.JWTBearerRequest{
				Assertion:    "eyJ.assertion.sig",
				ClientID:     "client-basic",
				ClientSecret: "secret-basic",
				DPoPProof:    "eyJ.proof.sig",
				HTTPMethod:   http.MethodPost,
				// Scheme from the (non-TLS) request, host from Host, path only:
				// the query string must not leak into htu.
				HTTPURL: "http://as.example.com/oauth/token",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &capturingJWTBearer{resp: &input.JWTBearerResponse{
				AccessToken: "at", TokenType: "Bearer", ExpiresIn: 900, Scope: "read",
			}}
			h := &oauthHandler{jwtBearer: fake, obs: observability.NewNoop()}

			rec := postJWTBearer(t, h, tc.form, tc.headers)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
			}
			if fake.got != tc.want {
				t.Errorf("service request:\n got %+v\nwant %+v", fake.got, tc.want)
			}
		})
	}
}

// The success body is the plain token response with no refresh_token key
// (jwt-bearer never issues one) and the RFC 6749 no-store cache headers.
func TestHandleJWTBearer_SuccessResponse(t *testing.T) {
	fake := &capturingJWTBearer{resp: &input.JWTBearerResponse{
		AccessToken: "issued-access-token",
		TokenType:   "DPoP",
		ExpiresIn:   900,
		Scope:       "read",
	}}
	h := &oauthHandler{jwtBearer: fake, obs: observability.NewNoop()}

	rec := postJWTBearer(t, h, url.Values{"assertion": {"a.b.c"}, "client_id": {"c"}}, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	for header, want := range map[string]string{
		"Content-Type":  "application/json",
		"Cache-Control": "no-store",
		"Pragma":        "no-cache",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	body := decodeJSONBody(t, rec)
	if body["access_token"] != "issued-access-token" {
		t.Errorf("access_token = %v", body["access_token"])
	}
	if body["token_type"] != "DPoP" {
		t.Errorf("token_type = %v, want DPoP", body["token_type"])
	}
	if body["expires_in"] != float64(900) {
		t.Errorf("expires_in = %v, want 900", body["expires_in"])
	}
	if body["scope"] != "read" {
		t.Errorf("scope = %v, want read", body["scope"])
	}
	if _, present := body["refresh_token"]; present {
		t.Error("refresh_token must be absent from a jwt-bearer response")
	}
}

// Service errors go through the shared token error writer, so the grant
// inherits the endpoint's status and error-code mapping.
func TestHandleJWTBearer_ServiceErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   string
		wantWWW    bool
	}{
		{"invalid_client is 401 with a challenge", domain.ErrInvalidClient, http.StatusUnauthorized, "invalid_client", true},
		{"invalid_grant is 400", domain.ErrInvalidGrant, http.StatusBadRequest, "invalid_grant", false},
		{"invalid_dpop_proof is 400", domain.ErrDPoPInvalidProof, http.StatusBadRequest, "invalid_dpop_proof", false},
		{"opaque error is a 500 with no detail leaked", errors.New("store exploded"), http.StatusInternalServerError, "server_error", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &capturingJWTBearer{err: tc.err}
			h := &oauthHandler{jwtBearer: fake, obs: observability.NewNoop()}

			rec := postJWTBearer(t, h, url.Values{"assertion": {"a.b.c"}, "client_id": {"c"}}, nil)

			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
			body := decodeJSONBody(t, rec)
			if body["error"] != tc.wantCode {
				t.Errorf("error = %v, want %s", body["error"], tc.wantCode)
			}
			if hasWWW := rec.Header().Get("WWW-Authenticate") != ""; hasWWW != tc.wantWWW {
				t.Errorf("WWW-Authenticate present = %v, want %v", hasWWW, tc.wantWWW)
			}
			if desc, _ := body["error_description"].(string); tc.wantStatus == http.StatusInternalServerError && strings.Contains(desc, "exploded") {
				t.Errorf("internal error text leaked to the client: %q", desc)
			}
		})
	}
}
