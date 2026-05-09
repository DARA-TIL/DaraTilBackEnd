package notificationUC

import (
	"DaraTilBackendV2/internal/application/services"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"DaraTilBackendV2/internal/infrastructure/logger"
	"context"

	"go.uber.org/zap"
)

type CreateUC struct {
	repo     repo.NotificationRepo
	notifSub services.NotificationSubscriber
}

func NewCreateUC(repo repo.NotificationRepo) *CreateUC {
	return &CreateUC{repo: repo}
}
func (uc *CreateUC) Execute(ctx context.Context, notification models.Notification) (*models.Notification, error) {
	return uc.repo.Create(ctx, notification)
}

func (uc *CreateUC) Handle(ctx context.Context, notif models.Notification) {
	notification, err := uc.Execute(ctx, notif)
	if err != nil {
		logger.Error("failed to create notification", zap.Error(err))
		return
	}
	logger.Info("notification created", zap.Any("notification", notification))
	uc.Notify(ctx, *notification)
}

func (uc *CreateUC) Notify(ctx context.Context, notif models.Notification) {
	uc.notifSub.Handle(ctx, notif)
}

func (uc *CreateUC) AddSubscriber(sub services.NotificationSubscriber) {
	uc.notifSub = sub
}
