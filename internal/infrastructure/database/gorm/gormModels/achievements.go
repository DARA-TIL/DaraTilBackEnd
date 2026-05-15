package gormModels

import (
	"DaraTilBackendV2/internal/domain/models"

	"gorm.io/gorm"
)

type Achievement struct {
	gorm.Model
	Name        string
	Description string
	Action      models.Actions
	Quantity    uint
	IconURL     string

	UserAchievements []UserAchievement `gorm:"foreignKey:AchievementID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type UserAchievement struct {
	ID            uint
	UserID        uint `gorm:"not null;uniqueIndex:user_achievement_idx"`
	AchievementID uint `gorm:"not null;uniqueIndex:user_achievement_idx"`
	Quantity      uint `gorm:"default:0"`
	Achieved      bool `gorm:"default:false"`

	User        User        `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
	Achievement Achievement `gorm:"foreignKey:AchievementID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}
