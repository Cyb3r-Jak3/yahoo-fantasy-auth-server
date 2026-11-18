package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/valkey-io/valkey-go"
	"go.uber.org/zap"
)

// A refresh binding ties a refresh token to the registration it was issued
// for. Only a hash of the token is stored. POST /refresh refuses any token
// that does not match its registration's binding, so a leaked refresh token
// alone cannot be used to mint access tokens through this service.

func refreshKey(registrationID string) string { return "yfo:refresh:" + registrationID }

func hashRefreshToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// saveRefreshBinding records the refresh token's hash for a registration. The
// TTL slides forward on every refresh.
func saveRefreshBinding(ctx context.Context, c valkey.Client, registrationID, refreshToken string, ttl time.Duration) error {
	return c.Do(ctx, c.B().Set().Key(refreshKey(registrationID)).Value(hashRefreshToken(refreshToken)).Ex(ttl).Build()).Error()
}

// checkRefreshBinding reports whether refreshToken is the one bound to the
// registration. A missing binding is a mismatch, not an error.
func checkRefreshBinding(ctx context.Context, c valkey.Client, registrationID, refreshToken string) (bool, error) {
	stored, err := c.Do(ctx, c.B().Get().Key(refreshKey(registrationID)).Build()).ToString()
	if valkey.IsValkeyNil(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(hashRefreshToken(refreshToken))) == 1, nil
}

type refreshRequest struct {
	RegistrationID string `json:"registration_id"`
	RefreshToken   string `json:"refresh_token"`
}

// yahooRefreshError is a rejection from Yahoo's token endpoint.
type yahooRefreshError struct {
	StatusCode int
	Code       string
}

// clientMisconfigured reports whether Yahoo rejected the app's client id or
// secret (for example invalid_client or INVALID_CONSUMER_KEY) rather than the
// refresh token.
func (e *yahooRefreshError) clientMisconfigured() bool {
	code := strings.ToLower(e.Code)
	return strings.Contains(code, "client") || strings.Contains(code, "consumer")
}

func (e *yahooRefreshError) Error() string {
	return fmt.Sprintf("yahoo token endpoint returned %d: %s", e.StatusCode, e.Code)
}

// refreshYahooToken exchanges a refresh token at Yahoo. Yahoo expects
// redirect_uri on refresh requests, which oauth2.Config does not send, so
// the request is built by hand.
func refreshYahooToken(ctx context.Context, refreshToken string) (TokenRecord, error) {
	var rec TokenRecord
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"redirect_uri":  {oauthConfig.RedirectURL},
		"client_id":     {oauthConfig.ClientID},
		"client_secret": {oauthConfig.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oauthConfig.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return rec, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(oauthConfig.ClientID), url.QueryEscape(oauthConfig.ClientSecret))
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return rec, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return rec, err
	}
	var out struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		Error        string `json:"error"`
	}
	_ = json.Unmarshal(body, &out)
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		return rec, &yahooRefreshError{StatusCode: resp.StatusCode, Code: out.Error}
	}
	rec = TokenRecord{
		AccessToken:   out.AccessToken,
		RefreshToken:  out.RefreshToken,
		RetrieveToken: out.TokenType,
	}
	if rec.RefreshToken == "" {
		rec.RefreshToken = refreshToken
	}
	if out.ExpiresIn > 0 {
		rec.ExpiresAt = time.Now().Add(time.Duration(out.ExpiresIn) * time.Second).Unix()
	}
	return rec, nil
}

// refreshHandler serves POST /refresh. The caller sends the registration ID
// it signed in with and its current refresh token, and gets a new token
// record back.
func refreshHandler(valkeyClient valkey.Client, bindingTTL time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req refreshRequest
		if err := json.NewDecoder(io.LimitReader(c.Request.Body, 1<<16)).Decode(&req); err != nil || req.RegistrationID == "" || req.RefreshToken == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "registration_id and refresh_token are required"})
			return
		}
		ctx := c.Request.Context()
		ok, err := checkRefreshBinding(ctx, valkeyClient, req.RegistrationID, req.RefreshToken)
		if err != nil {
			logger.Error("failed to load refresh binding", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load refresh binding"})
			return
		}
		if !ok {
			logger.Warn("refresh rejected: token does not match registration", zap.String("registration_id", req.RegistrationID))
			c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token is not valid for this registration"})
			return
		}
		rec, err := refreshYahooToken(ctx, req.RefreshToken)
		var yerr *yahooRefreshError
		switch {
		case errors.As(err, &yerr) && yerr.clientMisconfigured():
			// Yahoo rejected this service's own credentials, not the caller's
			// token. Keep the binding so callers recover once config is fixed.
			logger.Error("yahoo rejected the client credentials", zap.Error(err))
			c.JSON(http.StatusBadGateway, gin.H{"error": "yahoo rejected the oauth service's client credentials"})
			return
		case errors.As(err, &yerr) && yerr.StatusCode >= 400 && yerr.StatusCode < 500:
			// The refresh token is dead; drop its binding so it cannot be retried.
			logger.Warn("yahoo rejected refresh token", zap.String("registration_id", req.RegistrationID), zap.Error(err))
			if derr := valkeyClient.Do(ctx, valkeyClient.B().Del().Key(refreshKey(req.RegistrationID)).Build()).Error(); derr != nil {
				logger.Error("failed to delete refresh binding", zap.Error(derr))
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "yahoo rejected the refresh token, sign in again"})
			return
		case err != nil:
			logger.Error("failed to refresh token with yahoo", zap.Error(err))
			c.JSON(http.StatusBadGateway, gin.H{"error": "failed to refresh token with yahoo"})
			return
		}
		rec.RegistrationID = req.RegistrationID
		if err := saveRefreshBinding(ctx, valkeyClient, req.RegistrationID, rec.RefreshToken, bindingTTL); err != nil {
			// Yahoo already issued the token, so hand it over anyway. If the
			// refresh token rotated, the next refresh fails and the caller
			// signs in again.
			logger.Error("failed to save refresh binding", zap.Error(err))
		}
		c.JSON(http.StatusOK, rec)
	}
}
