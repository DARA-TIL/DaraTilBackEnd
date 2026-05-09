package notificationUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"

	"go.uber.org/zap"
)

type GetAllUC struct {
	repo repo.NotificationRepo
}

func NewGetAllUC(repo repo.NotificationRepo) *GetAllUC {
	return &GetAllUC{repo: repo}
}
func (uc *GetAllUC) Execute(ctx context.Context, params models.NotificationParams) ([]models.Notification, error) {
	notifs, err := uc.repo.GetAllNotifications(ctx, params)
	if err != nil {
		return nil, err
	}
	err = uc.repo.CreateReadNotifications(ctx, notifs, *params.UserID)
	if err != nil {
		logger.Info("Failed To create read notifs for user", zap.Uint("user_id", *params.UserID))
	}
	return notifs, err
}
