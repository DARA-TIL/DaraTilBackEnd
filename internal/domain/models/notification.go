package models

import (
	"time"
)

type NotificationScope string

const (
	NotificationScopeUser   NotificationScope = "user"
	NotificationScopeGlobal NotificationScope = "global"
)

type NotificationType string

const (
	NotificationTypeSystem NotificationType = "system"
	NotificationTypeEvent  NotificationType = "event"
	NotificationTypeStreak NotificationType = "streak"
	NotificationTypeReward NotificationType = "reward"
	NotifLogOut            NotificationType = "logOut"
)

type Notification struct {
	ID uint

	Title   string
	Message string
	Type    NotificationType

	Scope  NotificationScope
	UserID *uint

	IsActive  bool
	CreatedAt time.Time
	EntityID  *uint
	Reads     []NotificationRead
}
type NotificationRead struct {
	ID uint

	NotificationID uint
	UserID         uint

	ReadAt *time.Time

	Notification Notification
	User         User
}

type NotificationParams struct {
	Type    *NotificationType
	Scope   *NotificationScope
	NotSeen *bool
	Limit   *int
	UserID  *uint
}
type UpdateNotificationParams struct {
	ID uint

	Title   *string
	Message *string
	Type    *NotificationType
	Scope   *NotificationScope

	IsActive *bool
}
