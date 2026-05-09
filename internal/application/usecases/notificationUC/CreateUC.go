package notificationUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.NotificationRepo
}

func NewCreateUC(repo repo.NotificationRepo) *CreateUC {
	return &CreateUC{repo: repo}
}
func (uc *CreateUC) Execute(ctx context.Context, notification models.Notification) (*models.Notification, error) {
	return uc.repo.Create(ctx, notification)
}
