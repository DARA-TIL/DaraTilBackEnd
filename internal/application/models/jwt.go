package models

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

type UserClaims struct {
	UserID   int
	Username string
	Email    string
	Role     string
}

type CustomClaims struct {
	UserID   int
	Username string
	Email    string
	Role     string
	jwt.RegisteredClaims
}
type IssueTokenResult struct {
	AccessToken  string
	RefreshToken string
	RefreshExp   time.Time
}
type TokenMeta struct {
	Device    string
	IpAddress string
	UserAgent string
}
