package models

import (
	"time"

	"gorm.io/gorm"
)

type Token struct {
	gorm.Model
	UserID           uint      `gorm:"not null" json:"userId;index"`
	RefreshTokenHash string    `gorm:"not null" json:"refreshTokenHash;index" `
	Device           string    `gorm:"not null" json:"device"`
	IpAddress        string    `gorm:"not null" json:"ipAddress"`
	UserAgent        string    `gorm:"not null" json:"userAgent"`
	IsRevoked        bool      `gorm:"not null;default:false" json:"isRevoked"`
	Expires          time.Time `gorm:"not null" json:"expires"`
	LastUsed         time.Time `json:"lastUsed"`
	User             User      `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
