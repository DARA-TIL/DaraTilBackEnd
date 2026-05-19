package gormModels

import (
	"DaraTilBackendV2/internal/domain/models"

	"gorm.io/gorm"
)

type SpeechTest struct {
	gorm.Model

	KzText     string                  `gorm:"type:text;not null"`
	RuText     string                  `gorm:"type:text;not null"`
	EnText     string                  `gorm:"type:text;not null"`
	Difficulty models.SpeechDifficulty `gorm:"type:varchar(20);not null;index"`

	SessionTests []SpeechTestSessionTest `gorm:"foreignKey:TestID"`
}

type SpeechTestSession struct {
	gorm.Model

	UserID uint `gorm:"not null;index"`

	SessionTests []SpeechTestSessionTest `gorm:"foreignKey:SessionID"`

	CorrectCount int  `gorm:"not null;default:0"`
	IsEnded      bool `gorm:"not null;default:false"`

	User User `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type SpeechTestSessionTest struct {
	gorm.Model

	SessionID uint `gorm:"not null;index"`
	TestID    uint `gorm:"not null;index"`

	IsShown    bool `gorm:"not null;default:false"`
	IsAnswered bool `gorm:"not null;default:false"`
	IsCorrect  bool `gorm:"not null;default:false"`

	Session SpeechTestSession `gorm:"foreignKey:SessionID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Test    SpeechTest        `gorm:"foreignKey:TestID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
