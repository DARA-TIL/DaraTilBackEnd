package gormModels

import (
	"time"

	"gorm.io/gorm"
)

type Lesson struct {
	gorm.Model
	Name          string `gorm:"not null"`
	Description   string `gorm:"not null"`
	ImageUrl      string
	Author        string        `gorm:"not null"`
	Reward        int           `gorm:"not null"`
	RequiredLevel int           `gorm:"not null"`
	Blocks        []LessonBlock `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Test          Test          `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type LessonBlock struct {
	gorm.Model
	Name        string `gorm:"not null"`
	ContentType string `gorm:"not null"`
	ContentUrl  string
	ContentText string
	LessonID    uint `gorm:"not null"`
	Position    int  `gorm:"not null"`
}
type LessonResult struct {
	gorm.Model
	LessonID uint      `gorm:"not null"`
	UserID   uint      `gorm:"not null"`
	TestID   uint      `gorm:"not null"`
	Result   uint      `gorm:"not null"`
	Pass     bool      `gorm:"not null"`
	PassTime time.Time `gorm:"not null"`
}
