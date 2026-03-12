package regionTraditionTranslationsUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByTraditionIDUC struct {
	repo repo.RegionTraditionTranslationRepo
}

func NewGetByTraditionIDUC(repo repo.RegionTraditionTranslationRepo) *GetByTraditionIDUC {
	return &GetByTraditionIDUC{repo: repo}
}

func (uc *GetByTraditionIDUC) Execute(ctx context.Context, traditionID uint) ([]models.RegionTraditionsTranslation, error) {
	return uc.repo.GetByTraditionID(ctx, traditionID)
}
