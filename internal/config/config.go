package config

import (
	"github.com/kelseyhightower/envconfig"
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
