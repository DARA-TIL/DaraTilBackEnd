package timeEventUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type CreateUC struct {
	repo repo.TimeEventRepo
}

func NewCreateUC(repo repo.TimeEventRepo) *CreateUC {
	return &CreateUC{repo: repo}
}

func (uc *CreateUC) Execute(ctx context.Context, event models.TimeEvent) (*models.TimeEvent, error) {
	return uc.repo.Create(ctx, event)
}
