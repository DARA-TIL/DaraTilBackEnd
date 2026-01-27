package gormModels

import "gorm.io/gorm"

type Lesson struct {
	gorm.Model
	Name          string `gorm:"not null"`
	Description   string `gorm:"not null"`
	ImageUrl      string
	Author        string        `gorm:"not null"`
	Reward        int           `gorm:"not null"`
	RequiredLevel int           `gorm:"not null"`
	Blocks        []LessonBlock `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
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
