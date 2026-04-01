package services

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type Notifier interface {
	Notify(ctx context.Context, notif NotificationPayload)
	AddSubscriber(sub NotificationSubscriber)
}

type NotificationSubscriber interface {
	Handle(ctx context.Context, notif NotificationPayload)
}

type NotificationPayload interface {
	GetNotification() Notification
}

type Notification struct {
	UserID uint
	Type   models.NotificationTrigger
}

func (n Notification) GetNotification() Notification {
	return n
}

type StreakNotification struct {
	Notification
	Streak int
}

func (n StreakNotification) GetNotification() Notification {
	return n.Notification
}

type AchievementNotification struct {
	Notification
	AchievementID uint
}

func (n AchievementNotification) GetNotification() Notification {
	return n.Notification
}
