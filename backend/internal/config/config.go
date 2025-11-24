package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Port              string
	DatabaseURL       string
	JwtAccessSecret   string
	JwtRefreshSecret  string
	JwtAccessExpires  int
	JwtRefreshExpires int
}

func Load() *Config {
	cfg := &Config{
		Port:              MustEnvStr("PORT"),
		DatabaseURL:       MustEnvStr("DATABASE_URL"),
		JwtAccessSecret:   MustEnvStr("JWT_ACCESS_SECRET"),
		JwtRefreshSecret:  MustEnvStr("JWT_REFRESH_SECRET"),
		JwtAccessExpires:  MustEnvInt("JWT_ACCESS_EXPIRES_MIN"),
		JwtRefreshExpires: MustEnvInt("JWT_REFRESH_EXPIRES_HOURS"),
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
