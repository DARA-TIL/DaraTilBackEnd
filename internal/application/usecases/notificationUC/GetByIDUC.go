package notificationUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.NotificationRepo
}

func NewGetByIDUC(repo repo.NotificationRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}
func (uc *GetByIDUC) Execute(ctx context.Context, id, userID uint) (*models.Notification, error) {
	return uc.repo.GetNotificationByID(ctx, id, userID)
}
