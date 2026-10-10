package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/mock"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/yahoo"
)

const testTimeout = 10 * time.Minute

func TestMain(m *testing.M) {
	logger = zap.NewNop()
	os.Exit(m.Run())
}

func setup(t *testing.T) (*mock.Client, http.Handler) {
	t.Helper()
	client := mock.NewClient(gomock.NewController(t))
	oauthConfig = &oauth2.Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  "https://example.com/oauth2/callback",
		Endpoint:     oauth2.Endpoint{TokenURL: "http://127.0.0.1:0/token"},
	}
	return client, newRouter(context.Background(), client, testTimeout, "test", false)
}

func do(h http.Handler, method, path string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
	return w
}

func tokenServer(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestKeys(t *testing.T) {
	if got := registrationKey("abc"); got != "yfo:registration:abc" {
		t.Errorf("registrationKey = %q", got)
	}
	if got := tokenKey("abc"); got != "yfo:token:abc" {
		t.Errorf("tokenKey = %q", got)
	}
}

func TestSaveToken(t *testing.T) {
	rec := TokenRecord{RegistrationID: "id", AccessToken: "a", RefreshToken: "r", RetrieveToken: "bearer", ExpiresAt: 123}
	b, _ := json.Marshal(rec)

	t.Run("success", func(t *testing.T) {
		client, _ := setup(t)
		client.EXPECT().Do(gomock.Any(), mock.Match("SET", "yfo:token:id", string(b), "EX", "600")).Return(mock.Result(mock.ValkeyString("OK")))
		if err := saveToken(context.Background(), client, "id", rec, testTimeout); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("error", func(t *testing.T) {
		client, _ := setup(t)
		client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(mock.ErrorResult(errors.New("boom")))
		if err := saveToken(context.Background(), client, "id", rec, testTimeout); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestLoadToken(t *testing.T) {
	rec := TokenRecord{RegistrationID: "id", AccessToken: "a", RefreshToken: "r", ExpiresAt: 5}
	b, _ := json.Marshal(rec)

	t.Run("success", func(t *testing.T) {
		client, _ := setup(t)
		client.EXPECT().Do(gomock.Any(), mock.Match("GET", "yfo:token:id")).Return(mock.Result(mock.ValkeyBlobString(string(b))))
		got, err := loadToken(context.Background(), client, "id")
		if err != nil || got != rec {
			t.Fatalf("got %+v, err %v", got, err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		client, _ := setup(t)
		client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(mock.Result(mock.ValkeyNil()))
		if _, err := loadToken(context.Background(), client, "id"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("bad json", func(t *testing.T) {
		client, _ := setup(t)
		client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(mock.Result(mock.ValkeyBlobString("{not json")))
		if _, err := loadToken(context.Background(), client, "id"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestReady(t *testing.T) {
	_, h := setup(t)
	w := do(h, http.MethodGet, "/ready")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ready") {
		t.Errorf("got %d %s", w.Code, w.Body)
	}
}

func TestHealth(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		client, h := setup(t)
		client.EXPECT().Do(gomock.Any(), mock.Match("PING")).Return(mock.Result(mock.ValkeyString("PONG")))
		if w := do(h, http.MethodGet, "/health"); w.Code != http.StatusOK {
			t.Errorf("got %d", w.Code)
		}
	})
	t.Run("unhealthy", func(t *testing.T) {
		client, h := setup(t)
		client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(mock.ErrorResult(errors.New("down")))
		if w := do(h, http.MethodGet, "/health"); w.Code != http.StatusServiceUnavailable {
			t.Errorf("got %d", w.Code)
		}
	})
}

func TestRegister(t *testing.T) {
	client, h := setup(t)
	client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(mock.Result(mock.ValkeyString("OK")))
	w := do(h, http.MethodPost, "/register")
	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	var body struct {
		RegistrationID string    `json:"registration_id"`
		ExpiresAt      time.Time `json:"expires_at"`
		URL            string    `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.RegistrationID == "" || !strings.HasSuffix(body.URL, "/register/"+body.RegistrationID) {
		t.Errorf("unexpected body: %+v", body)
	}
	if !body.ExpiresAt.After(time.Now()) {
		t.Errorf("expires_at not in future: %v", body.ExpiresAt)
	}
}

func TestRegisterRedirect(t *testing.T) {
	future := time.Now().Add(time.Hour).Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).Format(time.RFC3339)

	tests := []struct {
		name   string
		result valkey.ValkeyResult
		want   int
	}{
		{"valid", mock.Result(mock.ValkeyBlobString(future)), http.StatusFound},
		{"expired", mock.Result(mock.ValkeyBlobString(past)), http.StatusGone},
		{"garbage timestamp", mock.Result(mock.ValkeyBlobString("nope")), http.StatusGone},
		{"not found", mock.Result(mock.ValkeyNil()), http.StatusNotFound},
		{"error", mock.ErrorResult(errors.New("x")), http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, h := setup(t)
			client.EXPECT().Do(gomock.Any(), mock.Match("GET", "yfo:registration:rid")).Return(tt.result)
			w := do(h, http.MethodGet, "/register/rid")
			if w.Code != tt.want {
				t.Fatalf("got %d, want %d", w.Code, tt.want)
			}
			if tt.want != http.StatusFound {
				return
			}
			loc, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if got := loc.Scheme + "://" + loc.Host + loc.Path; got != yahoo.Endpoint.AuthURL {
				t.Errorf("redirected to %q, want %q", got, yahoo.Endpoint.AuthURL)
			}
			q := loc.Query()
			if q.Get("client_id") != "test-client" || q.Get("state") != "rid" ||
				q.Get("response_type") != "code" || q.Get("redirect_uri") != "https://example.com/oauth2/callback" {
				t.Errorf("bad query: %v", q)
			}
		})
	}
}

func TestCallback(t *testing.T) {
	future := mock.Result(mock.ValkeyBlobString(time.Now().Add(time.Hour).Format(time.RFC3339)))
	past := mock.Result(mock.ValkeyBlobString(time.Now().Add(-time.Hour).Format(time.RFC3339)))
	const callback = "/oauth2/callback?code=c&state=s"

	t.Run("provider error", func(t *testing.T) {
		_, h := setup(t)
		if w := do(h, http.MethodGet, "/oauth2/callback?error=access_denied"); w.Code != http.StatusBadRequest {
			t.Errorf("got %d", w.Code)
		}
	})
	t.Run("unknown registration", func(t *testing.T) {
		client, h := setup(t)
		client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(mock.Result(mock.ValkeyNil()))
		if w := do(h, http.MethodGet, callback); w.Code != http.StatusNotFound {
			t.Errorf("got %d", w.Code)
		}
	})
	t.Run("expired", func(t *testing.T) {
		client, h := setup(t)
		client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(past)
		if w := do(h, http.MethodGet, callback); w.Code != http.StatusGone {
			t.Errorf("got %d", w.Code)
		}
	})
	t.Run("exchange fails", func(t *testing.T) {
		client, h := setup(t)
		oauthConfig.Endpoint.TokenURL = tokenServer(t, http.StatusBadRequest, `{"error":"invalid_grant"}`)
		client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(future)
		if w := do(h, http.MethodGet, callback); w.Code != http.StatusInternalServerError {
			t.Errorf("got %d", w.Code)
		}
	})
	t.Run("success", func(t *testing.T) {
		client, h := setup(t)
		oauthConfig.Endpoint.TokenURL = tokenServer(t, http.StatusOK, `{"access_token":"at","refresh_token":"rt","token_type":"bearer","expires_in":3600}`)
		gomock.InOrder(
			client.EXPECT().Do(gomock.Any(), mock.Match("GET", "yfo:registration:s")).Return(future),
			client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(mock.Result(mock.ValkeyString("OK"))),
		)
		w := do(h, http.MethodGet, callback)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "successful") {
			t.Errorf("got %d %s", w.Code, w.Body)
		}
	})
	t.Run("save fails", func(t *testing.T) {
		client, h := setup(t)
		oauthConfig.Endpoint.TokenURL = tokenServer(t, http.StatusOK, `{"access_token":"at","token_type":"bearer"}`)
		gomock.InOrder(
			client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(future),
			client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(mock.ErrorResult(errors.New("x"))),
		)
		if w := do(h, http.MethodGet, callback); w.Code != http.StatusInternalServerError {
			t.Errorf("got %d", w.Code)
		}
	})
}

func TestGetToken(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		client, h := setup(t)
		b, _ := json.Marshal(TokenRecord{RegistrationID: "rid", AccessToken: "at", RefreshToken: "rt"})
		client.EXPECT().Do(gomock.Any(), mock.Match("GET", "yfo:token:rid")).Return(mock.Result(mock.ValkeyBlobString(string(b))))
		w := do(h, http.MethodGet, "/token/rid")
		if w.Code != http.StatusOK {
			t.Fatalf("got %d", w.Code)
		}
		var got TokenRecord
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.AccessToken != "at" {
			t.Errorf("body %s err %v", w.Body, err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		client, h := setup(t)
		client.EXPECT().Do(gomock.Any(), gomock.Any()).Return(mock.Result(mock.ValkeyNil()))
		if w := do(h, http.MethodGet, "/token/rid"); w.Code != http.StatusNotFound {
			t.Errorf("got %d", w.Code)
		}
	})
}
