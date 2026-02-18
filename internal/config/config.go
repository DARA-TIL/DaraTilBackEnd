package config

import (
	"log"

	"github.com/gorilla/sessions"
	"github.com/kelseyhightower/envconfig"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Jwt      JWTConfig
	Oauth    OauthConfig
	Session  SessionConfig
	Smtp     SmtpConfig
	Gemini   GeminiConfig
}

type ServerConfig struct {
	Port        string `envconfig:"PORT"`
	FrontendUrl string `envconfig:"FRONTEND_URL"`
	MobileUrl   string `envconfig:"MOBILE_URL"`
	BaseUrl     string `envconfig:"BASE_URL"`
}
type DatabaseConfig struct {
	DatabaseUrl string `envconfig:"DATABASE_URL"`
}
type JWTConfig struct {
	JwtAccessSecret        string `envconfig:"JWT_ACCESS_SECRET"`
	JwtRefreshSecret       string `envconfig:"JWT_REFRESH_SECRET"`
	JwtAccessExpiresMin    int    `envconfig:"JWT_ACCESS_EXPIRES_MIN"`
	JwtRefreshExpiresHours int    `envconfig:"JWT_REFRESH_EXPIRES_HOURS"`
}
type OauthConfig struct {
	GoogleClientId     string `envconfig:"GOOGLE_CLIENT_ID"`
	GoogleClientSecret string `envconfig:"GOOGLE_CLIENT_SECRET"`
	GithubClientId     string `envconfig:"GITHUB_CLIENT_ID"`
	GithubClientSecret string `envconfig:"GITHUB_CLIENT_SECRET"`
}
type SessionConfig struct {
	SessionSecret string `envconfig:"SESSION_SECRET"`
}
type SmtpConfig struct {
	SmtpUser string `envconfig:"SMTP_USER"`
	SmtpPass string `envconfig:"SMTP_PASSWORD"`
}
type GeminiConfig struct {
	GeminiApiKey string `envconfig:"GEMINI_API_KEY"`
}

func LoadConfig() (*Config, error) {
	cfg := Config{}
	err := envconfig.Process("", &cfg)
	if err != nil {
		return &cfg, err
	}
	return &cfg, nil
}
func (c *Config) SetupGoogleOAuth() {
	callbackURL := c.Server.BaseUrl + "/api/auth/google/callback"

	goth.UseProviders(
		google.New(
			c.Oauth.GoogleClientId,
			c.Oauth.GoogleClientSecret,
			callbackURL,
			"email", "profile",
		),
	)
}

func (c *Config) SetupGithubOAuth() {
	callbackURL := c.Server.BaseUrl + "/api/auth/github/callback"
	goth.UseProviders(
		github.New(
			c.Oauth.GithubClientId,
			c.Oauth.GithubClientSecret,
			callbackURL,
			"user"),
	)
}

func (c *Config) SetupSessionStore() {
	secret := c.Session.SessionSecret
	if secret == "" {
		log.Fatal("SESSION_SECRET is not set")
	}
	store := sessions.NewCookieStore([]byte(secret))
	store.Options.HttpOnly = true
	store.Options.Secure = false
	store.Options.SameSite = 2
	gothic.Store = store
}
