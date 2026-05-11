package repo

import (
	"DaraTilBackendV2/internal/domain/models"
	"context"
)

type NotificationRepo interface {
	Create(ctx context.Context, notification models.Notification) (*models.Notification, error)
	GetNotificationByID(ctx context.Context, notificationID, userID uint) (*models.Notification, error)
	GetAllNotifications(ctx context.Context, params models.NotificationParams) ([]models.Notification, error)
	Update(ctx context.Context, params models.UpdateNotificationParams) (*models.Notification, error)
	Delete(ctx context.Context, notificationID uint) error
	CreateReadNotifications(ctx context.Context, notifications []models.Notification, userID uint) error
	DeleteAllNotificationsForUser(ctx context.Context, userID uint) error
	DeleteNotificationForUser(ctx context.Context, notifID, userID uint) error
}
