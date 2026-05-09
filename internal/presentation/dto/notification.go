package dto

import (
	"DaraTilBackendV2/internal/domain/models"
	"time"
)

type Notification struct {
	ID uint `json:"id"`

	Title   string                  `json:"title"`
	Message string                  `json:"message"`
	Type    models.NotificationType `json:"type"`

	Scope  models.NotificationScope `json:"scope"`
	UserID *uint                    `json:"userId,omitempty"`

	IsActive bool `json:"isActive"`

	IsRead bool       `json:"isRead"`
	ReadAt *time.Time `json:"readAt,omitempty"`

	CreatedAt time.Time `json:"createdAt,omitempty"`
}

type GetNotificationsResponse struct {
	Notifications []Notification `json:"notifications"`
	Unread        int            `json:"unread"`
}

type CreateNotificationRequest struct {
	Title   string `json:"title" binding:"required"`
	Message string `json:"message" binding:"required"`

	Type  models.NotificationType  `json:"type" binding:"required"`
	Scope models.NotificationScope `json:"scope" binding:"required"`

	UserID *uint `json:"userId,omitempty"`
}
type UpdateNotificationRequest struct {
	ID      uint    `json:"id" binding:"required"`
	Title   *string `json:"title,omitempty"`
	Message *string `json:"message,omitempty"`

	Type  *models.NotificationType  `json:"type,omitempty"`
	Scope *models.NotificationScope `json:"scope,omitempty"`

	IsActive *bool `json:"isActive,omitempty"`
}

type GetNotificationsQuery struct {
	Type    *models.NotificationType  `form:"type"`
	Scope   *models.NotificationScope `form:"scope"`
	NotSeen *bool                     `form:"notSeen"`
	Limit   *int                      `form:"limit"`
}
