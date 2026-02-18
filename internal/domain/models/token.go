package models

import (
	"time"
)

type Token struct {
	ID               uint
	UserID           uint
	RefreshTokenHash string
	Device           string
	IpAddress        string
	UserAgent        string
	IsRevoked        bool
	Expires          time.Time
	LastUsed         time.Time
	User             User
}
