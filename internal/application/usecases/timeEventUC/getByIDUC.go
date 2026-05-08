package timeEventUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.TimeEventRepo
}

func NewGetbyIDUC(repo repo.TimeEventRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}
func (uc *GetByIDUC) Execute(ctx context.Context, id uint) (*models.TimeEvent, error) {
	return uc.repo.GetByID(ctx, id)
}
