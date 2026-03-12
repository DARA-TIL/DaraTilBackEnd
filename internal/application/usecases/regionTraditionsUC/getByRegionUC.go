package regionTraditionsUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByRegionUC struct {
	repo repo.RegionTraditionRepo
}

func NewGetByRegionUC(repo repo.RegionTraditionRepo) *GetByRegionUC {
	return &GetByRegionUC{repo: repo}
}

func (uc *GetByRegionUC) Execute(ctx context.Context, regionID uint) ([]models.RegionTraditions, error) {
	return uc.repo.GetByRegionID(ctx, regionID)
}
