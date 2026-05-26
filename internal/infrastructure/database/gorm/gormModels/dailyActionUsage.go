package gormModels

import "time"

type DailyActionUsage struct {
	ID uint `gorm:"primaryKey"`

	UserID uint `gorm:"not null;uniqueIndex:idx_user_action_date"`

	Action string `gorm:"type:varchar(100);not null;uniqueIndex:idx_user_action_date"`

	UsageDate time.Time `gorm:"type:date;not null;uniqueIndex:idx_user_action_date"`

	Count int `gorm:"not null;default:0"`

	CreatedAt time.Time `gorm:"autoCreateTime"`
	UpdatedAt time.Time `gorm:"autoUpdateTime"`
}
