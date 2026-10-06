package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime/debug"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/gin-gonic/gin"
	"github.com/urfave/cli/v3"
	"github.com/valkey-io/valkey-go"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/yahoo"
)

var (
	version       = "DEV"
	date          = "unknown"
	commit        = "unknown"
	logger        *zap.Logger
	versionString = fmt.Sprintf("%s (commit: %s, date: %s)", version, commit, date)
	oauthConfig   *oauth2.Config
)

func main() {
	startTime := time.Now()
	var err error
	logger, err = zap.NewProduction()
	if err != nil {
		fmt.Printf("Error creating logger: %s\n", err)
		os.Exit(1)
	}

	if buildInfo, available := debug.ReadBuildInfo(); available {
		versionString = fmt.Sprintf("%s (built %s with %s, commit %s)", version, date, buildInfo.GoVersion, commit)
	} else {
		versionString = fmt.Sprintf("%s (built %s, commit %s)", version, date, commit)
		logger.Warn("Build info not available, using fallback version string")
	}

	app := &cli.Command{
		Name:  "yahoo-fantasy-oauth",
		Usage: "A command-line tool for Yahoo Fantasy Sports OAuth authentication",
		Authors: []any{
			"Cyb3rJak3 <git@cyberjake.xyz>",
		},
		Version: versionString,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{"l"},
				Value:   "info",
				Usage:   "Set the logging level (debug, info, warn, error)",
				Sources: cli.EnvVars("LOG_LEVEL"),
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Value:   8080,
				Sources: cli.EnvVars("SERVER_PORT"),
			},
			&cli.StringFlag{
				Name:    "address",
				Aliases: []string{"a"},
				Value:   "127.0.0.1",
				Sources: cli.EnvVars("SERVER_ADDRESS"),
			},
			&cli.StringFlag{
				Name:    "client-id",
				Aliases: []string{"c"},
				Usage:   "Client ID for your Yahoo application",
				Sources: cli.EnvVars("YAHOO_CLIENT_ID"),
			},
			&cli.StringFlag{
				Name:    "client-secret",
				Aliases: []string{"s"},
				Usage:   "Client secret for your Yahoo application",
				Sources: cli.EnvVars("YAHOO_CLIENT_SECRET"),
			},
			&cli.StringFlag{
				Name:    "redirect-uri",
				Aliases: []string{"r"},
				Usage:   "Redirect URI for your Yahoo application",
				Sources: cli.EnvVars("YAHOO_REDIRECT_URI"),
			},
			&cli.StringFlag{
				Name:    "redis-url",
				Usage:   "URL for your Redis instance (e.g., redis://localhost:6379)",
				Value:   "redis://localhost:6379",
				Sources: cli.EnvVars("REDIS_URL"),
			},
			&cli.StringFlag{
				Name:    "gin-mode",
				Usage:   "Set the Gin mode (debug, release, test)",
				Value:   "release",
				Sources: cli.EnvVars("GIN_MODE"),
				Hidden:  true,
			},
			&cli.DurationFlag{
				Name:    "registration-timeout",
				Usage:   "Set the timeout duration for registration requests (e.g., 30s, 1m)",
				Value:   10 * time.Minute,
				Sources: cli.EnvVars("REGISTRATION_TIMEOUT"),
			},
		},
		Action:                run,
		EnableShellCompletion: true,
	}
	sort.Sort(cli.FlagsByName(app.Flags))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err = app.Run(ctx, os.Args)
	logger.Debug("Run took", zap.Duration("duration", time.Since(startTime)))
	if err != nil {
		fmt.Printf("Error running app: %s\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd *cli.Command) error {
	logLevel := cmd.String("log-level")
	switch logLevel {
	case "debug":
		logger, _ = zap.NewDevelopment()
	case "info":
		logger, _ = zap.NewProduction()
	case "warn":
		cfg := zap.NewProductionConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.WarnLevel)
		logger, _ = cfg.Build()
	case "error":
		cfg := zap.NewProductionConfig()
		cfg.Level = zap.NewAtomicLevelAt(zap.ErrorLevel)
		logger, _ = cfg.Build()
	}
	if cmd.String("client-id") == "" || cmd.String("client-secret") == "" || cmd.String("redirect-uri") == "" {
		return fmt.Errorf("client-id, client-secret, and redirect-uri must be provided")
	}
	if cmd.String("redis-url") == "" {
		return fmt.Errorf("redis-url must be provided")
	}
	valkeyURL, err := valkey.ParseURL(cmd.String("redis-url"))
	if err != nil {
		logger.Error("invalid redis-url", zap.String("redis-url", cmd.String("redis-url")), zap.Error(err))
		return fmt.Errorf("invalid redis-url: %w", err)
	}
	valkeyClient, err := valkey.NewClient(valkeyURL)
	if err != nil {
		logger.Error("failed to create valkey client", zap.Error(err))
		return fmt.Errorf("failed to create valkey client: %w", err)
	}
	defer valkeyClient.Close()

	oauthConfig = &oauth2.Config{
		ClientID:     cmd.String("client-id"),
		RedirectURL:  cmd.String("redirect-uri"),
		ClientSecret: cmd.String("client-secret"),
		Endpoint:     yahoo.Endpoint,
	}
	registrationTimeout := cmd.Duration("registration-timeout")
	gin.SetMode(cmd.String("gin-mode"))
	r := gin.Default()
	r.GET("/ready", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})
	r.GET("/health", func(c *gin.Context) {
		valkeyStatus := valkeyClient.Do(ctx, valkeyClient.B().Ping().Build())
		if valkeyStatus.Error() != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "error": valkeyStatus.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
	r.POST("/register", func(c *gin.Context) {
		registrationID := uuid.New().String()
		expiresAt := time.Now().Add(registrationTimeout)
		valkeyClient.Do(c.Request.Context(), valkeyClient.B().Set().Key(registrationKey(registrationID)).Value(expiresAt.Format(time.RFC3339)).Ex(registrationTimeout).Build())
		c.JSON(http.StatusOK, gin.H{"registration_id": registrationID, "expires_at": expiresAt, "url": fmt.Sprintf("https://%s/register/%s", c.Request.Host, registrationID)})
	})
	r.GET("/register/:registration_id", func(c *gin.Context) {
		registrationID := c.Param("registration_id")
		valkeyStatus := valkeyClient.Do(c.Request.Context(), valkeyClient.B().Get().Key(registrationKey(registrationID)).Build())
		if valkeyStatus.Error() != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "registration ID not found"})
			return
		}
		expiresAtStr, err := valkeyStatus.ToString()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve expiration time"})
			return
		}
		if expiresAt, err := time.Parse(time.RFC3339, expiresAtStr); err != nil || time.Now().After(expiresAt) {
			c.JSON(http.StatusGone, gin.H{"error": "registration ID has expired"})
			return
		}
		redirectURL, err := url.Parse(yahoo.Endpoint.AuthURL)
		if err != nil {
			logger.Error("failed to parse redirect URL", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to parse redirect URL"})
			return
		}
		redirectURL.RawQuery = url.Values{
			"client_id":     {oauthConfig.ClientID},
			"redirect_uri":  {oauthConfig.RedirectURL},
			"response_type": {"code"},
			"state":         {registrationID},
		}.Encode()
		logger.Debug("Redirecting to Yahoo OAuth2 authorization URL", zap.String("url", redirectURL.String()))
		c.Redirect(302, redirectURL.String())
	})

	r.GET("/oauth2/callback", func(c *gin.Context) {
		code := c.Query("code")
		state := c.Query("state")
		errorParam := c.Query("error")
		if errorParam != "" {
			logger.Warn("OAuth2 callback returned an error", zap.String("error", errorParam), zap.String("state", state))
			c.JSON(http.StatusBadRequest, gin.H{"error": errorParam})
			return
		}
		registration := valkeyClient.Do(c.Request.Context(), valkeyClient.B().Get().Key(registrationKey(state)).Build())
		if registration.Error() != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "registration ID not found"})
			return
		}
		expiresAtStr, err := registration.ToString()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to retrieve expiration time"})
			return
		}
		if expiresAt, err := time.Parse(time.RFC3339, expiresAtStr); err != nil || time.Now().After(expiresAt) {
			c.JSON(http.StatusGone, gin.H{"error": "registration ID has expired"})
			return
		}
		basicToken, err := oauthConfig.Exchange(c.Request.Context(), code)
		if err != nil {
			logger.Error("failed to exchange code for token", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to exchange code for token"})
			return
		}
		tokenRecord := TokenRecord{
			RegistrationID: state,
			AccessToken:    basicToken.AccessToken,
			RefreshToken:   basicToken.RefreshToken,
			RetrieveToken:  basicToken.TokenType,
			ExpiresAt:      basicToken.Expiry.Unix(),
		}
		if err := saveToken(c.Request.Context(), valkeyClient, state, tokenRecord, registrationTimeout); err != nil {
			logger.Error("failed to save token", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save token"})
			return
		}
		c.String(http.StatusOK, "OAuth2 authentication successful. You can now close this window.")
	})
	r.GET("/token/:registration_id", func(c *gin.Context) {
		registrationID := c.Param("registration_id")
		tokenRecord, err := loadToken(c.Request.Context(), valkeyClient, registrationID)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "token not found"})
			return
		}
		c.Header("Content-Type", "application/json+oauthv1")
		c.JSON(http.StatusOK, tokenRecord)
	})

	return r.Run(fmt.Sprintf("%s:%d", cmd.String("address"), cmd.Int("port")))
}

type TokenRecord struct {
	RegistrationID string `json:"registration_id"`
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	RetrieveToken  string `json:"retrieve_token"`
	ExpiresAt      int64  `json:"expires_at,omitempty"`
}

func registrationKey(registrationID string) string { return "yfo:registration:" + registrationID }
func tokenKey(registrationID string) string        { return "yfo:token:" + registrationID }

func saveToken(ctx context.Context, c valkey.Client, registrationID string, rec TokenRecord, expire time.Duration) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return c.Do(ctx, c.B().Set().Key(tokenKey(registrationID)).Value(string(b)).Ex(expire).Build()).Error()
}

func loadToken(ctx context.Context, c valkey.Client, registrationID string) (TokenRecord, error) {
	var rec TokenRecord
	b, err := c.Do(ctx, c.B().Get().Key(tokenKey(registrationID)).Build()).AsBytes()
	if err != nil {
		return rec, err
	}
	return rec, json.Unmarshal(b, &rec)
}
