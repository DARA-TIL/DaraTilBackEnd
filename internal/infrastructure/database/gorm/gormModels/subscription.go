package gormModels

import (
	"DaraTilBackendV2/internal/domain/models"
	"time"
)

type Subscription struct {
	ID uint `gorm:"primaryKey"`

	UserID uint `gorm:"not null;index"`

	Status models.SubscriptionStatus `gorm:"type:varchar(20);not null;default:'active';index"`

	PlanID uint             `gorm:"not null;index"`
	Plan   SubscriptionPlan `gorm:"foreignKey:PlanID;references:ID;constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`

	ActiveUntil time.Time  `gorm:"not null;index"`
	CancelledAt *time.Time `gorm:"index"`

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}

type SubscriptionPlan struct {
	ID uint `gorm:"primaryKey"`

	Name        string  `gorm:"type:varchar(100);not null;uniqueIndex"`
	Description *string `gorm:"type:text"`

	Price        int `gorm:"not null"`
	DurationDays int `gorm:"not null"`

	IsActive bool `gorm:"not null;default:true;index"`

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}
