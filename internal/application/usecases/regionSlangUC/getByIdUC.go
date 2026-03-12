package regionSlangUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.RegionSlangRepo
}

func NewGetByIDUC(repo repo.RegionSlangRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}
func (uc *GetByIDUC) Execute(ctx context.Context, id uint) (*models.RegionSlang, error) {
	return uc.repo.GetByID(ctx, id)
}
