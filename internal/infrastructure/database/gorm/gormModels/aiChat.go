package gormModels

import "gorm.io/gorm"

type AIChat struct {
	gorm.Model

	Name   string `gorm:"type:varchar(255);not null"`
	UserID uint   `gorm:"not null;index"`

	User     *User           `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Messages []AIChatMessage `gorm:"foreignKey:ChatID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type AIChatMessage struct {
	gorm.Model

	ChatID uint    `gorm:"not null;index"`
	Chat   *AIChat `gorm:"foreignKey:ChatID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`

	Message    string `gorm:"type:text;not null"`
	SenderType string `gorm:"type:varchar(20);not null"`

	UserID *uint `gorm:"index"`
	User   *User `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}
