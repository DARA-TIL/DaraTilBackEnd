package notificationUC

import (
	errs "DaraTilBackendV2/internal/domain/domErr"
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateUC struct {
	repo repo.NotificationRepo
}

func NewUpdateUC(repo repo.NotificationRepo) *UpdateUC {
	return &UpdateUC{repo: repo}
}
func (uc *UpdateUC) Execute(
	ctx context.Context,
	params models.UpdateNotificationParams,
) (*models.Notification, error) {
	if params.ID == 0 {
		return nil, errs.ErrInvalidInput
	}

	if params.Title == nil &&
		params.Message == nil &&
		params.Type == nil &&
		params.Scope == nil &&
		params.IsActive == nil {
		return nil, errs.ErrInvalidInput
	}

	return uc.repo.Update(ctx, params)
}
