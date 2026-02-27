package gormModels

import (
	"time"

	"gorm.io/gorm"
)

type Streak struct {
	gorm.Model
	UserID        uint      `gorm:"uniqueIndex"`
	CurrentStreak int       `gorm:"not null; default:0"`
	LongestStreak int       `gorm:"not null; default:0"`
	LastActivity  time.Time `gorm:"type:date"`
}
