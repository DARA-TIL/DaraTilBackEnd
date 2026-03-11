package regionUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByRegionUC struct {
	repo repo.RegionSlangRepo
}

func NewGetByRegionUC(repo repo.RegionSlangRepo) *GetByRegionUC {
	return &GetByRegionUC{repo: repo}
}

func (uc *GetByRegionUC) Execute(ctx context.Context, regionID uint) ([]models.RegionSlang, error) {
	return uc.repo.GetByRegionID(ctx, regionID)
}
