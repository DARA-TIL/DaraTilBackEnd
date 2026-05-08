package timeEventUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetAllUC struct {
	repo repo.TimeEventRepo
}

func NewGetAllUC(repo repo.TimeEventRepo) *GetAllUC {
	return &GetAllUC{repo: repo}
}
func (uc *GetAllUC) Execute(ctx context.Context, params models.TimeEventParams) ([]models.TimeEvent, error) {
	return uc.repo.GetAll(ctx, params)
}
