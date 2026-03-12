package regionTraditionTranslationsUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.RegionTraditionTranslationRepo
}

func NewGetByIDUC(repo repo.RegionTraditionTranslationRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}
func (uc *GetByIDUC) Execute(ctx context.Context, id uint) (*models.RegionTraditionsTranslation, error) {
	return uc.repo.GetByID(ctx, id)
}
