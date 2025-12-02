package models

import (
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username     string  `gorm:"unique; not null" json:"username"`
	Email        string  `gorm:"unique; not null" json:"email"`
	Password     string  `gorm:"not null" json:"password"`
	Avatar       string  `json:"avatar"`
	Role         string  `gorm:"not null" json:"role"`
	Level        int     `gorm:"not null; default:0" json:"level"`
	Experience   int     `gorm:"not null; default:0" json:"experience"`
	AuthProvider string  `gorm:"not null; " json:"authProvider"`
	Tokens       []Token `gorm:"foreignKey:UserID" json:"tokens,omitempty"`
}
