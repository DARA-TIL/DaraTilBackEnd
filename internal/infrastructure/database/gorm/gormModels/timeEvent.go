package gormModels

import (
	"time"

	"gorm.io/gorm"
)

type TimeEvent struct {
	gorm.Model
	Name         string `gorm:"not null"`
	Description  string
	RewardFirst  uint
	RewardSecond uint
	RewardThird  uint
	EventType    string        `gorm:"not null"`
	Duration     time.Duration `gorm:"not null"`
	StartDate    time.Time     `gorm:"not null"`
	EndDate      time.Time     `gorm:"not null"`
	Users        []User        `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE;OnDelete:CASCADE;"`
	IsActive     bool          `gorm:"not null;default:true"`
}

type TimeEventParticipant struct {
	ID          uint
	UserID      uint `gorm:"not null"`
	TimeEventID uint `gorm:"not null"`
	Count       int  `gorm:"not null;default:0"`
	IsActive    bool `gorm:"not null;default:true"`
	Place       int

	TimeEvent TimeEvent `gorm:"foreignKey:TimeEventID;constraint:OnUpdate:CASCADE;OnDelete:CASCADE;"`
	User      User      `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE;OnDelete:CASCADE;"`
}
