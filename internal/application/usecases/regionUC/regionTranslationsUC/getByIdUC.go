package regionTranslationsUC

import (
	"DaraTilBackendV2/internal/domain/models"
	"DaraTilBackendV2/internal/domain/repo"
	"context"
)

type GetByIDUC struct {
	repo repo.RegionTranslationRepo
}

func NewGetByIDUC(repo repo.RegionTranslationRepo) *GetByIDUC {
	return &GetByIDUC{repo: repo}
}
func (uc *GetByIDUC) Execute(ctx context.Context, id uint) (*models.RegionTranslation, error) {
	return uc.repo.GetByID(ctx, id)
}
