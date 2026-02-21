package gormModels

import "gorm.io/gorm"

type QuestionOption struct {
	gorm.Model
	QuestionID uint   `gorm:"not null"`
	IsCorrect  bool   `gorm:"DEFAULT:false"`
	Text       string `gorm:"type:text"`
}

type Question struct {
	gorm.Model
	TestID  uint             `gorm:"not null"`
	Text    string           `gorm:"not null"`
	Options []QuestionOption `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE"`
}

type Test struct {
	gorm.Model
	LessonID  uint       `gorm:"not null;uniqueIndex"`
	Questions []Question `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
