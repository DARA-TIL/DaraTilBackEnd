package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	Username     string `gorm:"unique; not null"`
	Email        string `gorm:"unique; not null"`
	Password     string `gorm:"not null"`
	Avatar       string
	Role         string `gorm:"not null"`
	Level        int    `gorm:"not null; default:1"`
	Experience   int    `gorm:"not null; default:0"`
	AuthProvider string `gorm:"not null; "`
}
