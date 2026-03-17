package dto

import "DaraTilBackendV2/internal/domain/models"

type Achievement struct {
	ID          uint           `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Action      models.Actions `json:"action"`
	Quantity    uint           `json:"quantity"`
	IconURL     string         `json:"iconUrl"`

	UserAchievements []UserAchievement `json:"userAchievements"`
}
type UserAchievement struct {
	ID            uint `json:"id"`
	UserID        uint `json:"userId"`
	AchievementID uint `json:"achievementId"`
	Quantity      uint `json:"quantity"`
	Achieved      bool `json:"achieved"`
}
