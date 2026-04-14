package gormModels

import "gorm.io/gorm"

type UserProfile struct {
	gorm.Model
	UserID             uint                `gorm:"uniqueIndex"`
	PinnedAchievements []PinnedAchievement `gorm:"foreignKey:UserID;references:UserID;constraint:OnDelete:CASCADE,OnUpdate:CASCADE;"`
	WordsLearned       int                 `gorm:"default:0"`
	User               User                `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE, onUpdate:CASCADE;"`
}

type PinnedAchievement struct {
	gorm.Model
	AchievementID uint
	UserID        uint

	Achievement Achievement `gorm:"foreignKey:AchievementID;constraint:OnDelete:CASCADE;onUpdate:CASCADE;"`
	User        User        `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;onUpdate:CASCADE;"`
}
