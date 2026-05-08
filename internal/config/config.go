package config

import (
	"log"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/kelseyhightower/envconfig"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
)

type Config struct {
	Server          ServerConfig
	Database        DatabaseConfig
	Jwt             JWTConfig
	Oauth           OauthConfig
	Session         SessionConfig
	Smtp            SmtpConfig
	Gemini          GeminiConfig
	SessionSecurity SessionSecurity
	WSSecurity      WSSecurity
}

type WSSecurity struct {
	AllowedOrigins []string `envconfig:"ALLOWED_ORIGINS"`
}

type SessionSecurity struct {
	HttpOnly bool `envconfig:"SESSION_HTTP_ONLY" default:"true"`
	Secure   bool `envconfig:"SESSION_HTTP_SECURE" default:"false"`
	SameSite int  `envconfig:"SESSION_HTTP_SAME_SITE" default:"2"`
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
	cfg.SetupGithubOAuth()
	cfg.SetupGoogleOAuth()
	cfg.SetupSessionStore()
	return &cfg, nil
}
func (c *Config) SetupGoogleOAuth() {
	callbackURL := c.Server.BaseUrl + "/api/auth/google/callback"
	log.Println("Setting up Google OAuth")
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
	log.Println("Setting up Github OAuth")
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
	log.Println("Setting up session store")
	if secret == "" {
		log.Fatal("SESSION_SECRET is not set")
	}
	store := sessions.NewCookieStore([]byte(secret))
	httpOnly := c.SessionSecurity.HttpOnly
	secure := c.SessionSecurity.Secure
	sameSite := c.SessionSecurity.SameSite
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,
		HttpOnly: httpOnly,
		Secure:   secure,
		SameSite: http.SameSite(sameSite),
	}
	gothic.Store = store
}
