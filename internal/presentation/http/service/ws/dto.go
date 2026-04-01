package ws

import "DaraTilBackendV2/internal/domain/models"

type Notification struct {
	UserID uint                       `json:"userId"`
	Type   models.NotificationTrigger `json:"type"`
}

func (n Notification) GetType() models.NotificationTrigger {
	return n.Type
}

type StreakNotification struct {
	Notification
	Streak int `json:"streak"`
}

func (n StreakNotification) GetType() models.NotificationTrigger {
	return n.Type
}

type AchievementNotification struct {
	Notification
	AchievementID uint `json:"achievementId"`
}

func (n AchievementNotification) GetType() models.NotificationTrigger {
	return n.Type
}
