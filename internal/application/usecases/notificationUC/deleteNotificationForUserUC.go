package notificationUC

import (
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type DeleteNotificationForUserUC struct {
	repo repo.NotificationRepo
}

func NewDeleteNotificationForUserUC(repo repo.NotificationRepo) *DeleteNotificationForUserUC {
	return &DeleteNotificationForUserUC{repo: repo}
}
func (uc *DeleteNotificationForUserUC) Execute(ctx context.Context, notifID, userID uint) error {
	return uc.repo.DeleteNotificationForUser(ctx, notifID, userID)
}

type DeleteAllNotificationsForUserUC struct {
	repo repo.NotificationRepo
}

func NewDeleteAllNotificationsForUserUC(repo repo.NotificationRepo) *DeleteAllNotificationsForUserUC {
	return &DeleteAllNotificationsForUserUC{repo: repo}
}
func (uc *DeleteAllNotificationsForUserUC) Execute(ctx context.Context, userID uint) error {
	return uc.repo.DeleteAllNotificationsForUser(ctx, userID)
}
