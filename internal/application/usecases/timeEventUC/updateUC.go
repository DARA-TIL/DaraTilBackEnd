package timeEventUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type UpdateUC struct {
	repo repo.TimeEventRepo
}

func NewUpdateUC(repo repo.TimeEventRepo) *UpdateUC {
	return &UpdateUC{repo: repo}
}

func (uc *UpdateUC) Execute(ctx context.Context, event models.TimeEvent) (*models.TimeEvent, error) {
	if event.Status != "" {
		err := uc.repo.ChangeEventStatus(ctx, event.ID, event.Status)
		if err != nil {
			return nil, err
		}
		event.Status = ""
	}
	return uc.repo.Update(ctx, event)
}
