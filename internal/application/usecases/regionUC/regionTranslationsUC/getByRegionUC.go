package regionTranslationsUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByRegionUC struct {
	repo repo.RegionTranslationRepo
}

func NewGetByRegionUC(repo repo.RegionTranslationRepo) *GetByRegionUC {
	return &GetByRegionUC{repo: repo}
}

func (uc *GetByRegionUC) Execute(ctx context.Context, regionID uint) ([]models.RegionTranslation, error) {
	return uc.repo.GetByRegionID(ctx, regionID)
}
