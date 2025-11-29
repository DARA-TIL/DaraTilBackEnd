package config

import (
	"fmt"
	"log"
	"net/smtp"
	"os"
	"strconv"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/github"
	"github.com/markbates/goth/providers/google"
)

type Config struct {
	Port               string
	FrontendUrl        string
	BaseURL            string
	DatabaseURL        string
	JwtAccessSecret    string
	JwtRefreshSecret   string
	JwtAccessExpires   int
	JwtRefreshExpires  int
	GoogleClientID     string
	GoogleClientSecret string
	GithubClientID     string
	GithubClientSecret string
	SmtpUser           string
	SmtpPassword       string
	SessionSecret      string
}

func Load() *Config {
	cfg := &Config{
		Port:               MustEnvStr("PORT"),
		BaseURL:            MustEnvStr("BASE_URL"),
		DatabaseURL:        MustEnvStr("DATABASE_URL"),
		JwtAccessSecret:    MustEnvStr("JWT_ACCESS_SECRET"),
		JwtRefreshSecret:   MustEnvStr("JWT_REFRESH_SECRET"),
		JwtAccessExpires:   MustEnvInt("JWT_ACCESS_EXPIRES_MIN"),
		JwtRefreshExpires:  MustEnvInt("JWT_REFRESH_EXPIRES_HOURS"),
		GoogleClientID:     MustEnvStr("GOOGLE_CLIENT_ID"),
		GoogleClientSecret: MustEnvStr("Google_CLIENT_SECRET"),
		GithubClientID:     MustEnvStr("Github_CLIENT_ID"),
		GithubClientSecret: MustEnvStr("Github_CLIENT_SECRET"),
		SmtpUser:           MustEnvStr("SMTP_USER"),
		SmtpPassword:       MustEnvStr("SMTP_PASSWORD"),
		SessionSecret:      MustEnvStr("SESSION_SECRET"),
		FrontendUrl:        MustEnvStr("FRONTEND_URL"),
	}
	return cfg
}

func MustEnvStr(key string) string {
	val := os.Getenv(key)
	if val == "" {
		panic(fmt.Sprintf("environment variable %s must be set", key))
	}
	return val
}
func MustEnvInt(key string) int {
	val := MustEnvStr(key)
	i, err := strconv.Atoi(val)
	if err != nil {
		panic(fmt.Sprintf("environment variable %s must be an integer", key))
	}
	return i
}
func GetEnv(key string, def string) string {
	val := os.Getenv(key)
	if val == "" {
		return def
	}
	return val
}

func (c *Config) SetupGoogleOAuth() {
	callbackURL := c.BaseURL + "/api/auth/google/callback"

	goth.UseProviders(
		google.New(
			c.GoogleClientID,
			c.GoogleClientSecret,
			callbackURL,
			"email", "profile",
		),
	)
}

func (c *Config) SetupGithubOAuth() {
	callbackURL := c.BaseURL + "/api/auth/github/callback"
	goth.UseProviders(
		github.New(
			c.GithubClientID,
			c.GithubClientSecret,
			callbackURL,
			"user"),
	)
}

func (c *Config) SetupSessionStore() {
	secret := c.SessionSecret
	if secret == "" {
		log.Fatal("SESSION_SECRET is not set")
	}
	store := sessions.NewCookieStore([]byte(secret))
	store.Options.HttpOnly = true
	store.Options.Secure = false
	store.Options.SameSite = 2
	gothic.Store = store
}

func (c *Config) SmtpAuth() smtp.Auth {
	smtpHost := "smtp.gmail.com"
	username := c.SmtpUser
	password := c.SmtpPassword
	auth := smtp.PlainAuth("", username, password, smtpHost)
	return auth
}
