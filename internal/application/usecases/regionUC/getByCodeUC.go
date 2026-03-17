package regionUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByCodeUC struct {
	repo repo.RegionRepo
}

func NewGetByCodeUC(repo repo.RegionRepo) *GetByCodeUC {
	return &GetByCodeUC{repo: repo}
}
func (uc *GetByCodeUC) Execute(ctx context.Context, code string) (*models.Region, error) {
	return uc.repo.GetByCode(ctx, code)
}
