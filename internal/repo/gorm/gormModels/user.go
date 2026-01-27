package gormModels

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username     string `gorm:"unique; not null"`
	Email        string `gorm:"unique; not null"`
	Password     string `gorm:"not null"`
	Avatar       string
	Role         string       `gorm:"not null"`
	AuthProvider string       `gorm:"not null"`
	Progress     UserProgress `gorm:"constraint:OnDelete:CASCADE; OnUpdate:CASCADE;"`
	Tokens       []Token      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;"`
}

type UserProgress struct {
	gorm.Model
	UserID         uint `gorm:"not null"`
	Level          int  `gorm:"default:1"`
	XpTotal        int  `gorm:"default:0"`
	XpForNextLevel int  `gorm:"default:100"`
}
