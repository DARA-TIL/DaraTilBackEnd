package gormModels

import (
	"time"

	"gorm.io/gorm"
)

type Token struct {
	gorm.Model
	UserID           uint      `gorm:"not null;index"`
	RefreshTokenHash string    `gorm:"not null;index"`
	Device           string    `gorm:"not null"`
	IpAddress        string    `gorm:"not null"`
	UserAgent        string    `gorm:"not null"`
	IsRevoked        bool      `gorm:"not null;default:false"`
	Expires          time.Time `gorm:"not null"`
	LastUsed         time.Time
	User             User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
