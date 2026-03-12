package regionSlangTranslationsUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.RegionSlangTranslationRepo
}

func NewGetByIDUC(repo repo.RegionSlangTranslationRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}
func (uc *GetByIDUC) Execute(ctx context.Context, id uint) (*models.RegionSlangTranslation, error) {
	return uc.repo.GetByID(ctx, id)
}
