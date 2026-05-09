package gormModels

import (
	"time"

	"gorm.io/gorm"
)

type Notification struct {
	gorm.Model

	Title   string `gorm:"not null"`
	Message string `gorm:"not null"`
	Type    string `gorm:"not null"`

	Scope  string `gorm:"not null"`
	UserID *uint  `gorm:"index"`

	IsActive bool `gorm:"not null;default:true"`
	EntityID *uint

	Reads []NotificationRead `gorm:"foreignKey:NotificationID"`
}

type NotificationRead struct {
	gorm.Model

	NotificationID uint `gorm:"not null;index:idx_notification_reads_unique,unique"`
	UserID         uint `gorm:"not null;index:idx_notification_reads_unique,unique"`

	ReadAt *time.Time

	Notification Notification `gorm:"foreignKey:NotificationID;constraint:OnUpdate:CASCADE;OnDelete:CASCADE;"`
	User         User         `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE;OnDelete:CASCADE;"`
}
