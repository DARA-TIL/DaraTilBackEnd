package gormMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/infrastructure/database/gorm/gormModels"
)

func NotificationToGormModel(notification models.Notification) gormModels.Notification {
	return gormModels.Notification{
		Title:    notification.Title,
		Message:  notification.Message,
		Type:     string(notification.Type),
		Scope:    string(notification.Scope),
		UserID:   notification.UserID,
		EntityID: notification.EntityID,
		IsActive: notification.IsActive,
		Reads:    NotificationReadsToGormModel(notification.Reads),
	}
}

func GormNotificationToDomainModel(notification gormModels.Notification) models.Notification {
	return models.Notification{
		ID:        notification.ID,
		Title:     notification.Title,
		Message:   notification.Message,
		Type:      models.NotificationType(notification.Type),
		Scope:     models.NotificationScope(notification.Scope),
		UserID:    notification.UserID,
		EntityID:  notification.EntityID,
		IsActive:  notification.IsActive,
		CreatedAt: notification.CreatedAt,
		Reads:     GormNotificationReadsToDomainModel(notification.Reads),
	}
}

func NotificationsToGormModel(notifications []models.Notification) []gormModels.Notification {
	gormNotifications := make([]gormModels.Notification, 0, len(notifications))

	for _, notification := range notifications {
		gormNotifications = append(gormNotifications, NotificationToGormModel(notification))
	}

	return gormNotifications
}

func GormNotificationsToDomainModel(notifications []gormModels.Notification) []models.Notification {
	domainNotifications := make([]models.Notification, 0, len(notifications))

	for _, notification := range notifications {
		domainNotifications = append(domainNotifications, GormNotificationToDomainModel(notification))
	}

	return domainNotifications
}

func NotificationReadToGormModel(read models.NotificationRead) gormModels.NotificationRead {
	return gormModels.NotificationRead{
		NotificationID: read.NotificationID,
		UserID:         read.UserID,
		ReadAt:         read.ReadAt,
		Notification:   NotificationToGormModel(read.Notification),
		User:           UserToGormModel(read.User),
	}
}

func GormNotificationReadToDomainModel(read gormModels.NotificationRead) models.NotificationRead {
	return models.NotificationRead{
		ID:             read.ID,
		NotificationID: read.NotificationID,
		UserID:         read.UserID,
		ReadAt:         read.ReadAt,
		Notification:   GormNotificationToDomainModel(read.Notification),
		User:           GormUserToDomain(read.User),
	}
}

func NotificationReadsToGormModel(reads []models.NotificationRead) []gormModels.NotificationRead {
	gormReads := make([]gormModels.NotificationRead, 0, len(reads))

	for _, read := range reads {
		gormReads = append(gormReads, NotificationReadToGormModel(read))
	}

	return gormReads
}

func GormNotificationReadsToDomainModel(reads []gormModels.NotificationRead) []models.NotificationRead {
	domainReads := make([]models.NotificationRead, 0, len(reads))

	for _, read := range reads {
		domainReads = append(domainReads, GormNotificationReadToDomainModel(read))
	}

	return domainReads
}
