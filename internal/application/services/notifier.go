package services

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type Notifier interface {
	Notify(ctx context.Context, notif models.Notification)
	AddSubscriber(sub NotificationSubscriber)
}

type NotificationSubscriber interface {
	Handle(ctx context.Context, notif models.Notification)
}
