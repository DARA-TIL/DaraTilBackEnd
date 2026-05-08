package gormModels

import (
	"DaraTilBackendV2/internal/domain/models"
	"time"

	"gorm.io/gorm"
)

type TimeEvent struct {
	gorm.Model
	Name         string `gorm:"not null"`
	Description  string
	RewardFirst  int
	RewardSecond int
	RewardThird  int
	IsWeekly     bool                   `gorm:"default:false"`
	EventType    string                 `gorm:"not null"`
	Duration     time.Duration          `gorm:"not null"`
	StartDate    time.Time              `gorm:"not null"`
	EndDate      time.Time              `gorm:"not null"`
	Participants []TimeEventParticipant `gorm:"foreignKey:TimeEventID;constraint:OnUpdate:CASCADE;OnDelete:CASCADE;"`
	Status       models.TimeEventStatus `gorm:"not null;default:waiting"`
}

type TimeEventParticipant struct {
	ID          uint
	UserID      uint `gorm:"not null;uniqueIndex:timeEvent_user_idx"`
	TimeEventID uint `gorm:"not null;uniqueIndex:timeEvent_user_idx"`
	Count       int  `gorm:"not null;default:0"`
	IsActive    bool `gorm:"not null;default:true"`
	Place       int

	TimeEvent TimeEvent `gorm:"foreignKey:TimeEventID;constraint:OnUpdate:CASCADE;OnDelete:CASCADE;"`
	User      User      `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE;OnDelete:CASCADE;"`
}
