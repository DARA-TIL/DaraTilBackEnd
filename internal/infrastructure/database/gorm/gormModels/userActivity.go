package gormModels

import (
	"gorm.io/gorm"
)

type UserActivity struct {
	gorm.Model
	UserID     uint   `gorm:"not null"`
	Action     string `gorm:"not null"`
	EntityType string `gorm:"not null"`
	EntityID   uint   `gorm:"not null"`
}
