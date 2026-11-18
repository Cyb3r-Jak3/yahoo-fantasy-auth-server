package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/mock"
	"go.uber.org/mock/gomock"
)

const bindingTTLSeconds = "86400" // testBindingTTL

func doJSON(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	h.ServeHTTP(w, req)
	return w
}

// capturingTokenServer imitates Yahoo's token endpoint and records the last
// form it received.
func capturingTokenServer(t *testing.T, status int, body string) (string, *http.Request) {
	t.Helper()
	got := new(http.Request)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		*got = *r
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, got
}

func TestRefreshKey(t *testing.T) {
	if got := refreshKey("abc"); got != "yfo:refresh:abc" {
		t.Errorf("refreshKey = %q", got)
	}
	if hashRefreshToken("a") == hashRefreshToken("b") || len(hashRefreshToken("a")) != 64 {
		t.Error("unexpected hash")
	}
}

func TestRefreshRejectsBadRequests(t *testing.T) {
	for _, body := range []string{``, `{`, `{}`, `{"registration_id":"rid"}`, `{"refresh_token":"rt"}`} {
		_, h := setup(t)
		if w := doJSON(h, http.MethodPost, "/refresh", body); w.Code != http.StatusBadRequest {
			t.Errorf("body %q: got %d", body, w.Code)
		}
	}
}

func TestRefreshBinding(t *testing.T) {
	const body = `{"registration_id":"rid","refresh_token":"rt"}`
	tests := []struct {
		name   string
		stored valkey.ValkeyResult
		want   int
	}{
		{"no binding", mock.Result(mock.ValkeyNil()), http.StatusUnauthorized},
		{"other token", mock.Result(mock.ValkeyBlobString(hashRefreshToken("someone-else"))), http.StatusUnauthorized},
		{"valkey error", mock.ErrorResult(errors.New("down")), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, h := setup(t)
			// Yahoo must not be called when the binding does not match.
			url, got := capturingTokenServer(t, http.StatusOK, `{"access_token":"x"}`)
			oauthConfig.Endpoint.TokenURL = url
			client.EXPECT().Do(gomock.Any(), mock.Match("GET", "yfo:refresh:rid")).Return(tt.stored)
			if w := doJSON(h, http.MethodPost, "/refresh", body); w.Code != tt.want {
				t.Errorf("got %d %s, want %d", w.Code, w.Body, tt.want)
			}
			if got.Method != "" {
				t.Error("yahoo was called")
			}
		})
	}
}

func TestRefreshSuccess(t *testing.T) {
	client, h := setup(t)
	url, got := capturingTokenServer(t, http.StatusOK, `{"access_token":"at2","refresh_token":"rt2","token_type":"bearer","expires_in":3600}`)
	oauthConfig.Endpoint.TokenURL = url
	client.EXPECT().Do(gomock.Any(), mock.Match("GET", "yfo:refresh:rid")).Return(mock.Result(mock.ValkeyBlobString(hashRefreshToken("rt"))))
	// The binding moves to the rotated refresh token.
	client.EXPECT().Do(gomock.Any(), mock.Match("SET", "yfo:refresh:rid", hashRefreshToken("rt2"), "EX", bindingTTLSeconds)).Return(mock.Result(mock.ValkeyString("OK")))

	w := doJSON(h, http.MethodPost, "/refresh", `{"registration_id":"rid","refresh_token":"rt"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("got %d %s", w.Code, w.Body)
	}
	var rec TokenRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.RegistrationID != "rid" || rec.AccessToken != "at2" || rec.RefreshToken != "rt2" || rec.RetrieveToken != "bearer" {
		t.Errorf("record %+v", rec)
	}
	if d := time.Until(time.Unix(rec.ExpiresAt, 0)); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("expires_at %d", rec.ExpiresAt)
	}
	for k, want := range map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": "rt",
		"redirect_uri":  "https://example.com/oauth2/callback",
		"client_id":     "test-client",
	} {
		if v := got.PostForm.Get(k); v != want {
			t.Errorf("form %s = %q, want %q", k, v, want)
		}
	}
	if user, pass, ok := got.BasicAuth(); !ok || user != "test-client" || pass != "test-secret" {
		t.Errorf("basic auth %q %q %v", user, pass, ok)
	}
}

func TestRefreshKeepsTokenWhenYahooDoesNotRotate(t *testing.T) {
	client, h := setup(t)
	oauthConfig.Endpoint.TokenURL, _ = capturingTokenServer(t, http.StatusOK, `{"access_token":"at2","expires_in":3600}`)
	client.EXPECT().Do(gomock.Any(), mock.Match("GET", "yfo:refresh:rid")).Return(mock.Result(mock.ValkeyBlobString(hashRefreshToken("rt"))))
	client.EXPECT().Do(gomock.Any(), mock.Match("SET", "yfo:refresh:rid", hashRefreshToken("rt"), "EX", bindingTTLSeconds)).Return(mock.Result(mock.ValkeyString("OK")))
	w := doJSON(h, http.MethodPost, "/refresh", `{"registration_id":"rid","refresh_token":"rt"}`)
	var rec TokenRecord
	if err := json.Unmarshal(w.Body.Bytes(), &rec); err != nil || w.Code != http.StatusOK || rec.RefreshToken != "rt" {
		t.Errorf("got %d %s", w.Code, w.Body)
	}
}

func TestRefreshYahooRejects(t *testing.T) {
	client, h := setup(t)
	oauthConfig.Endpoint.TokenURL, _ = capturingTokenServer(t, http.StatusBadRequest, `{"error":"invalid_grant"}`)
	client.EXPECT().Do(gomock.Any(), mock.Match("GET", "yfo:refresh:rid")).Return(mock.Result(mock.ValkeyBlobString(hashRefreshToken("rt"))))
	client.EXPECT().Do(gomock.Any(), mock.Match("DEL", "yfo:refresh:rid")).Return(mock.Result(mock.ValkeyInt64(1)))
	if w := doJSON(h, http.MethodPost, "/refresh", `{"registration_id":"rid","refresh_token":"rt"}`); w.Code != http.StatusUnauthorized {
		t.Errorf("got %d %s", w.Code, w.Body)
	}
}

func TestRefreshYahooUnavailable(t *testing.T) {
	client, h := setup(t)
	oauthConfig.Endpoint.TokenURL, _ = capturingTokenServer(t, http.StatusServiceUnavailable, ``)
	// The binding is kept so the caller can retry.
	client.EXPECT().Do(gomock.Any(), mock.Match("GET", "yfo:refresh:rid")).Return(mock.Result(mock.ValkeyBlobString(hashRefreshToken("rt"))))
	if w := doJSON(h, http.MethodPost, "/refresh", `{"registration_id":"rid","refresh_token":"rt"}`); w.Code != http.StatusBadGateway {
		t.Errorf("got %d %s", w.Code, w.Body)
	}
}

func TestCallbackSavesRefreshBinding(t *testing.T) {
	client, h := setup(t)
	oauthConfig.Endpoint.TokenURL = tokenServer(t, http.StatusOK, `{"access_token":"at","refresh_token":"rt","token_type":"bearer","expires_in":3600}`)
	gomock.InOrder(
		client.EXPECT().Do(gomock.Any(), mock.Match("GET", "yfo:registration:s")).
			Return(mock.Result(mock.ValkeyBlobString(time.Now().Add(time.Hour).Format(time.RFC3339)))),
		client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(mock.Result(mock.ValkeyString("OK"))), // SET yfo:token:s
		client.EXPECT().Do(gomock.Any(), mock.Match("SET", "yfo:refresh:s", hashRefreshToken("rt"), "EX", bindingTTLSeconds)).
			Return(mock.Result(mock.ValkeyString("OK"))),
	)
	if w := do(h, http.MethodGet, "/oauth2/callback?code=c&state=s"); w.Code != http.StatusOK {
		t.Errorf("got %d %s", w.Code, w.Body)
	}
}

func TestRefreshClientMisconfiguredKeepsBinding(t *testing.T) {
	for _, code := range []string{"INVALID_CONSUMER_KEY", "invalid_client"} {
		client, h := setup(t)
		oauthConfig.Endpoint.TokenURL, _ = capturingTokenServer(t, http.StatusUnauthorized, `{"error":"`+code+`"}`)
		// Only the GET is expected: no DEL of the binding.
		client.EXPECT().Do(gomock.Any(), mock.Match("GET", "yfo:refresh:rid")).Return(mock.Result(mock.ValkeyBlobString(hashRefreshToken("rt"))))
		if w := doJSON(h, http.MethodPost, "/refresh", `{"registration_id":"rid","refresh_token":"rt"}`); w.Code != http.StatusBadGateway {
			t.Errorf("%s: got %d %s", code, w.Code, w.Body)
		}
	}
}
