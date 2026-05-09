package dtoMappers

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/presentation/dto"
	"time"
)

func NotificationToDto(notification models.Notification) dto.Notification {
	var readAt *time.Time

	if len(notification.Reads) > 0 {
		readAt = notification.Reads[0].ReadAt
	}

	return dto.Notification{
		ID: notification.ID,

		Title:   notification.Title,
		Message: notification.Message,
		Type:    notification.Type,

		Scope:  notification.Scope,
		UserID: notification.UserID,

		IsActive:  notification.IsActive,
		CreatedAt: notification.CreatedAt,

		IsRead: len(notification.Reads) > 0,
		ReadAt: readAt,
	}
}

func NotificationsToDto(notifications []models.Notification) dto.GetNotificationsResponse {
	result := make([]dto.Notification, 0, len(notifications))
	unread := 0
	for _, notification := range notifications {
		notifDto := NotificationToDto(notification)
		result = append(result, notifDto)
		if !notifDto.IsRead {
			unread++
		}
	}
	response := dto.GetNotificationsResponse{
		Notifications: result,
		Unread:        unread,
	}
	return response
}

func NotificationFromCreateRequest(req dto.CreateNotificationRequest) models.Notification {
	return models.Notification{
		Title:    req.Title,
		Message:  req.Message,
		Type:     req.Type,
		Scope:    req.Scope,
		UserID:   req.UserID,
		IsActive: true,
	}
}

func NotificationUpdateParamsFromRequest(
	req dto.UpdateNotificationRequest,
) models.UpdateNotificationParams {
	return models.UpdateNotificationParams{
		ID: req.ID,

		Title:   req.Title,
		Message: req.Message,
		Type:    req.Type,
		Scope:   req.Scope,

		IsActive: req.IsActive,
	}
}
func NotificationParamsFromQuery(
	req dto.GetNotificationsQuery,
	userID uint,
) models.NotificationParams {
	return models.NotificationParams{
		Type:    req.Type,
		Scope:   req.Scope,
		NotSeen: req.NotSeen,
		Limit:   req.Limit,
		UserID:  &userID,
	}
}
